package main

import (
	"database/sql"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/kilo666mj/gatekit/store"

	// Seeding a legacy schema opens SQLite directly rather than through
	// gatekit, so register the driver here instead of relying on gatekit's
	// choice of driver staying the same.
	_ "modernc.org/sqlite"
)

// The store itself is tested in gatekit. What needs covering here is the
// SSH-specific adapter: that a fingerprinted KEXINIT survives a round trip
// through the untyped metadata bag, and that a database written by the
// pre-gatekit sshgate still reads correctly through it.

func testFingerprint() SSHFingerprint {
	return SSHFingerprint{
		Hash:          "0123456789abcdef0123456789abcdef",
		Raw:           "raw-kexinit-blob",
		ClientID:      "SSH-2.0-OpenSSH_9.6",
		Kex:           "curve25519-sha256,ecdh-sha2-nistp256",
		HostKey:       "ssh-ed25519,rsa-sha2-512",
		CipherC2S:     "chacha20-poly1305@openssh.com",
		CipherS2C:     "aes256-gcm@openssh.com",
		MACC2S:        "hmac-sha2-256-etm@openssh.com",
		MACS2C:        "hmac-sha2-512-etm@openssh.com",
		CompressC2S:   "none",
		CompressS2C:   "zlib@openssh.com",
		FirstKexGuess: true,
	}
}

func TestSSHFingerprintRoundTripsThroughStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sshgate.db")
	st, err := NewStore(path)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	fp := testFingerprint()
	if _, err := st.Observe(store.Observation{
		Fingerprint: fp.Hash,
		IP:          "192.0.2.10",
		Meta:        fp.toMeta(),
	}, false); err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	// Re-open so values come back off disk as JSON rather than out of the
	// in-process map — in particular first_kex_guess as a real bool.
	reopened, err := NewStore(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() {
		if err := reopened.Close(); err != nil {
			t.Errorf("Close reopened store: %v", err)
		}
	}()

	entry, err := reopened.Get(fp.Hash)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got := sshMetaOf(entry); !reflect.DeepEqual(got, fp) {
		t.Errorf("round trip mismatch:\n got %+v\nwant %+v", got, fp)
	}
}

func TestSSHMetaOfEmptyEntry(t *testing.T) {
	// A placeholder row written by --register or a gatehub decision has no
	// metadata; it must render as a zero fingerprint rather than panic.
	got := sshMetaOf(Entry{Fingerprint: "abc"})
	if got.Hash != "abc" || got.ClientID != "" || got.FirstKexGuess {
		t.Errorf("sshMetaOf(empty) = %+v", got)
	}
}

// A database written by the pre-gatekit sshgate must keep its verdicts and
// still surface its SSH fields through the adapter. This is the migration
// that runs against the databases in service.
func TestOpensPreGatekitDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := db.Exec(`
		CREATE TABLE fingerprints (
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
		);
		CREATE TABLE fingerprint_ips (
			fp TEXT NOT NULL REFERENCES fingerprints(fp) ON DELETE CASCADE,
			ip TEXT NOT NULL, PRIMARY KEY (fp, ip)
		);
		INSERT INTO fingerprints VALUES ('fp1','approved','michael-laptop',
			'2026-01-01T00:00:00Z','2026-02-01T00:00:00Z',
			'SSH-2.0-OpenSSH_9.6','rawblob','curve25519-sha256','ssh-ed25519',
			'chacha20-poly1305@openssh.com','aes256-gcm@openssh.com',
			'hmac-sha2-256','hmac-sha2-512','none','none',1);
		INSERT INTO fingerprint_ips VALUES ('fp1','192.0.2.10');
	`); err != nil {
		t.Fatalf("seed legacy schema: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close legacy database: %v", err)
	}

	st, err := NewStore(path)
	if err != nil {
		t.Fatalf("NewStore on legacy db: %v", err)
	}
	defer func() {
		if err := st.Close(); err != nil {
			t.Errorf("close store: %v", err)
		}
	}()

	entry, err := st.Get("fp1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if entry.Status != StatusApproved || entry.Label != "michael-laptop" {
		t.Errorf("verdict lost: status=%q label=%q", entry.Status, entry.Label)
	}
	if len(entry.IPs) != 1 || entry.IPs[0] != "192.0.2.10" {
		t.Errorf("ips = %v", entry.IPs)
	}
	fp := sshMetaOf(entry)
	if fp.ClientID != "SSH-2.0-OpenSSH_9.6" || fp.Kex != "curve25519-sha256" {
		t.Errorf("ssh metadata = %+v", fp)
	}
	// The 0/1 integer column has to come back as a real bool, not a string.
	if !fp.FirstKexGuess {
		t.Errorf("first_kex_guess = %v, want true", fp.FirstKexGuess)
	}

	// A client that has never been seen must still be recordable against the
	// migrated schema — the legacy columns are NOT NULL, so this is where a
	// missing default would take the gate down on the first new connection.
	if _, err := st.Observe(store.Observation{
		Fingerprint: "brandnew",
		IP:          "192.0.2.99",
		Meta:        testFingerprint().toMeta(),
	}, false); err != nil {
		t.Fatalf("Observe new fingerprint on migrated db: %v", err)
	}
}
