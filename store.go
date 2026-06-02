package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

type Entry struct {
	Status        string   `json:"status"`
	Label         string   `json:"label,omitempty"`
	FirstSeen     Time     `json:"first_seen"`
	LastSeen      Time     `json:"last_seen"`
	IPs           []string `json:"ips,omitempty"`
	ClientID      string   `json:"client_id,omitempty"`
	Raw           string   `json:"raw,omitempty"`
	Kex           string   `json:"kex,omitempty"`
	HostKey       string   `json:"host_key,omitempty"`
	CipherC2S     string   `json:"cipher_c2s,omitempty"`
	CipherS2C     string   `json:"cipher_s2c,omitempty"`
	MACC2S        string   `json:"mac_c2s,omitempty"`
	MACS2C        string   `json:"mac_s2c,omitempty"`
	CompressC2S   string   `json:"compress_c2s,omitempty"`
	CompressS2C   string   `json:"compress_s2c,omitempty"`
	FirstKexGuess bool     `json:"first_kex_guess,omitempty"`
}

type Store struct {
	path string
	db   *sql.DB
}

func NewStore(path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("empty database path")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	store := &Store{path: path, db: db}
	if err := store.init(); err != nil {
		db.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) init() error {
	ctx := context.Background()
	for _, stmt := range []string{
		`PRAGMA busy_timeout = 5000`,
		`PRAGMA foreign_keys = ON`,
		`PRAGMA journal_mode = WAL`,
		`CREATE TABLE IF NOT EXISTS fingerprints (
			fp TEXT PRIMARY KEY,
			status TEXT NOT NULL,
			label TEXT NOT NULL DEFAULT '',
			first_seen TEXT NOT NULL,
			last_seen TEXT NOT NULL,
			client_id TEXT NOT NULL DEFAULT '',
			raw TEXT NOT NULL DEFAULT '',
			kex TEXT NOT NULL DEFAULT '',
			host_key TEXT NOT NULL DEFAULT '',
			cipher_c2s TEXT NOT NULL DEFAULT '',
			cipher_s2c TEXT NOT NULL DEFAULT '',
			mac_c2s TEXT NOT NULL DEFAULT '',
			mac_s2c TEXT NOT NULL DEFAULT '',
			compress_c2s TEXT NOT NULL DEFAULT '',
			compress_s2c TEXT NOT NULL DEFAULT '',
			first_kex_guess INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS fingerprint_ips (
			fp TEXT NOT NULL REFERENCES fingerprints(fp) ON DELETE CASCADE,
			ip TEXT NOT NULL,
			PRIMARY KEY (fp, ip)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_fingerprints_last_seen ON fingerprints(last_seen)`,
		`CREATE INDEX IF NOT EXISTS idx_fingerprint_ips_ip ON fingerprint_ips(ip)`,
	} {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	for _, column := range []struct {
		name string
		def  string
	}{
		{"cipher_s2c", "TEXT NOT NULL DEFAULT ''"},
		{"mac_s2c", "TEXT NOT NULL DEFAULT ''"},
		{"compress_s2c", "TEXT NOT NULL DEFAULT ''"},
	} {
		if err := s.addColumnIfMissing(ctx, "fingerprints", column.name, column.def); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) addColumnIfMissing(ctx context.Context, table, column, def string) error {
	rows, err := s.db.QueryContext(ctx, fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var cid, notnull, pk int
		var name, ctype string
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return err
		}
		if name == column {
			return rows.Close()
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", table, column, def))
	return err
}

func (s *Store) List() (map[string]Entry, error) {
	rows, err := s.db.Query(`
		SELECT fp, status, label, first_seen, last_seen, client_id, raw, kex,
			host_key, cipher_c2s, cipher_s2c, mac_c2s, mac_s2c,
			compress_c2s, compress_s2c, first_kex_guess
		FROM fingerprints`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make(map[string]Entry)
	for rows.Next() {
		var fp, firstSeen, lastSeen string
		var firstKexGuess int
		var e Entry
		if err := rows.Scan(
			&fp, &e.Status, &e.Label, &firstSeen, &lastSeen, &e.ClientID, &e.Raw,
			&e.Kex, &e.HostKey, &e.CipherC2S, &e.CipherS2C, &e.MACC2S, &e.MACS2C,
			&e.CompressC2S, &e.CompressS2C, &firstKexGuess,
		); err != nil {
			return nil, err
		}
		parsedFirstSeen, err := decodeTime(firstSeen)
		if err != nil {
			return nil, fmt.Errorf("decode first_seen for %s: %w", fp, err)
		}
		parsedLastSeen, err := decodeTime(lastSeen)
		if err != nil {
			return nil, fmt.Errorf("decode last_seen for %s: %w", fp, err)
		}
		e.FirstSeen = Time{Time: parsedFirstSeen}
		e.LastSeen = Time{Time: parsedLastSeen}
		e.FirstKexGuess = firstKexGuess != 0
		out[fp] = e
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	for fp, e := range out {
		ips, err := s.listIPs(fp)
		if err != nil {
			return nil, err
		}
		e.IPs = ips
		out[fp] = e
	}
	return out, nil
}

func (s *Store) Observe(fp SSHFingerprint, ip string, blockUnknown bool) (Entry, error) {
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Entry{}, err
	}
	defer tx.Rollback()

	now := encodeTime(time.Now())
	status := StatusPending
	if blockUnknown {
		status = StatusBlocked
	}
	// Insert on first sight; on conflict refresh only the observed metadata and
	// last_seen, leaving status, label, and first_seen intact. This preserves a
	// prior verdict (and a pre-approved placeholder row from UpsertStatus) while
	// still recording the latest handshake details.
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO fingerprints (
			fp, status, label, first_seen, last_seen, client_id, raw, kex,
			host_key, cipher_c2s, cipher_s2c, mac_c2s, mac_s2c,
			compress_c2s, compress_s2c, first_kex_guess
		) VALUES (?, ?, '', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(fp) DO UPDATE SET
			last_seen = excluded.last_seen,
			client_id = excluded.client_id,
			raw = excluded.raw,
			kex = excluded.kex,
			host_key = excluded.host_key,
			cipher_c2s = excluded.cipher_c2s,
			cipher_s2c = excluded.cipher_s2c,
			mac_c2s = excluded.mac_c2s,
			mac_s2c = excluded.mac_s2c,
			compress_c2s = excluded.compress_c2s,
			compress_s2c = excluded.compress_s2c,
			first_kex_guess = excluded.first_kex_guess`,
		fp.Hash, status, now, now, fp.ClientID, fp.Raw, fp.Kex,
		fp.HostKey, fp.CipherC2S, fp.CipherS2C, fp.MACC2S, fp.MACS2C,
		fp.CompressC2S, fp.CompressS2C, boolInt(fp.FirstKexGuess),
	); err != nil {
		return Entry{}, err
	}
	if ip != "" {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO fingerprint_ips (fp, ip) VALUES (?, ?)`, fp.Hash, ip); err != nil {
			return Entry{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return Entry{}, err
	}

	return s.get(fp.Hash)
}

// get loads a single fingerprint entry by hash. Used on the proxy hot path so
// each connection costs one indexed lookup instead of a full-table scan.
func (s *Store) get(fp string) (Entry, error) {
	var firstSeen, lastSeen string
	var firstKexGuess int
	var e Entry
	err := s.db.QueryRow(`
		SELECT status, label, first_seen, last_seen, client_id, raw, kex,
			host_key, cipher_c2s, cipher_s2c, mac_c2s, mac_s2c,
			compress_c2s, compress_s2c, first_kex_guess
		FROM fingerprints WHERE fp = ?`, fp).Scan(
		&e.Status, &e.Label, &firstSeen, &lastSeen, &e.ClientID, &e.Raw,
		&e.Kex, &e.HostKey, &e.CipherC2S, &e.CipherS2C, &e.MACC2S, &e.MACS2C,
		&e.CompressC2S, &e.CompressS2C, &firstKexGuess,
	)
	if err != nil {
		return Entry{}, err
	}
	parsedFirstSeen, err := decodeTime(firstSeen)
	if err != nil {
		return Entry{}, fmt.Errorf("decode first_seen for %s: %w", fp, err)
	}
	parsedLastSeen, err := decodeTime(lastSeen)
	if err != nil {
		return Entry{}, fmt.Errorf("decode last_seen for %s: %w", fp, err)
	}
	e.FirstSeen = Time{Time: parsedFirstSeen}
	e.LastSeen = Time{Time: parsedLastSeen}
	e.FirstKexGuess = firstKexGuess != 0
	ips, err := s.listIPs(fp)
	if err != nil {
		return Entry{}, err
	}
	e.IPs = ips
	return e, nil
}

func (s *Store) SetStatus(fp, status, label string) error {
	query := `UPDATE fingerprints SET status = ? WHERE fp = ?`
	args := []any{status, fp}
	if label != "" {
		query = `UPDATE fingerprints SET status = ?, label = ? WHERE fp = ?`
		args = []any{status, label, fp}
	}
	res, err := s.db.Exec(query, args...)
	if err != nil {
		return err
	}
	return requireAffected(res, fp)
}

// UpsertStatus sets the status (and optional label) for a fingerprint,
// inserting a placeholder row when the fingerprint has not been observed yet.
// This lets an operator pre-approve a known fingerprint before its first
// connection; Observe fills in the metadata columns on that first connection
// and leaves the status untouched.
func (s *Store) UpsertStatus(fp, status, label string) error {
	now := encodeTime(time.Now())
	_, err := s.db.Exec(`
		INSERT INTO fingerprints (fp, status, label, first_seen, last_seen)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(fp) DO UPDATE SET
			status = excluded.status,
			label = CASE WHEN excluded.label != '' THEN excluded.label ELSE fingerprints.label END`,
		fp, status, label, now, now)
	return err
}

func (s *Store) Label(fp, label string) error {
	res, err := s.db.Exec(`UPDATE fingerprints SET label = ? WHERE fp = ?`, label, fp)
	if err != nil {
		return err
	}
	return requireAffected(res, fp)
}

func (s *Store) Delete(fp string) error {
	res, err := s.db.Exec(`DELETE FROM fingerprints WHERE fp = ?`, fp)
	if err != nil {
		return err
	}
	return requireAffected(res, fp)
}

func (s *Store) PruneToLimit(max int) (int, error) {
	if max <= 0 {
		return 0, nil
	}
	ctx := context.Background()
	var count int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM fingerprints`).Scan(&count); err != nil {
		return 0, err
	}
	excess := count - max
	if excess <= 0 {
		return 0, nil
	}
	res, err := s.db.ExecContext(ctx, `
		DELETE FROM fingerprints
		WHERE fp IN (
			SELECT fp FROM fingerprints
			WHERE status != ?
			ORDER BY last_seen ASC
			LIMIT ?
		)`, StatusApproved, excess)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}

func (s *Store) listIPs(fp string) ([]string, error) {
	rows, err := s.db.Query(`SELECT ip FROM fingerprint_ips WHERE fp = ? ORDER BY ip`, fp)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ips []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		ips = append(ips, ip)
	}
	return ips, rows.Err()
}

func requireAffected(res sql.Result, fp string) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("fingerprint not found: %s", fp)
	}
	return nil
}

func encodeTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

func decodeTime(s string) (time.Time, error) {
	return time.Parse(time.RFC3339Nano, s)
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
