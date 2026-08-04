package main

import (
	"github.com/kilo666mj/gatekit/store"
)

// The fingerprint store itself lives in gatekit, shared with tlsgate. What
// stays here is the SSH-specific part: which columns the pre-gatekit schema
// used, and how an SSHFingerprint converts to and from the store's untyped
// metadata bag.

// Status and Entry are re-exported so the rest of the gate reads as it did
// before the store moved out.
type (
	Status = store.Status
	Entry  = store.Entry
)

// legacyColumns maps the typed columns of the pre-gatekit sshgate schema onto
// keys in the metadata bag. Databases in service still have these columns;
// gatekit folds them in once on open, so approvals, blocks, labels and history
// carry over untouched. The columns are left in place, so rolling back to a
// pre-gatekit binary still finds its schema.
var legacyColumns = []store.LegacyColumn{
	{Column: "client_id", MetaKey: "client_id"},
	{Column: "raw", MetaKey: "raw"},
	{Column: "kex", MetaKey: "kex"},
	{Column: "host_key", MetaKey: "host_key"},
	{Column: "cipher_c2s", MetaKey: "cipher_c2s"},
	{Column: "cipher_s2c", MetaKey: "cipher_s2c"},
	{Column: "mac_c2s", MetaKey: "mac_c2s"},
	{Column: "mac_s2c", MetaKey: "mac_s2c"},
	{Column: "compress_c2s", MetaKey: "compress_c2s"},
	{Column: "compress_s2c", MetaKey: "compress_s2c"},
	{Column: "first_kex_guess", MetaKey: "first_kex_guess", Kind: store.KindBool},
}

// NewStore opens the fingerprint database, folding a pre-gatekit schema into
// the metadata bag if it finds one.
func NewStore(path string) (*store.Store, error) {
	return store.Open(store.Options{Path: path, Legacy: legacyColumns})
}

// toMeta renders a fingerprinted KEXINIT into the store's metadata bag.
func (fp SSHFingerprint) toMeta() map[string]any {
	return map[string]any{
		"client_id":       fp.ClientID,
		"raw":             fp.Raw,
		"kex":             fp.Kex,
		"host_key":        fp.HostKey,
		"cipher_c2s":      fp.CipherC2S,
		"cipher_s2c":      fp.CipherS2C,
		"mac_c2s":         fp.MACC2S,
		"mac_s2c":         fp.MACS2C,
		"compress_c2s":    fp.CompressC2S,
		"compress_s2c":    fp.CompressS2C,
		"first_kex_guess": fp.FirstKexGuess,
	}
}

// sshMetaOf reads a stored entry's metadata bag back into an SSHFingerprint
// for display and correlation. Hash comes from the entry key rather than the
// bag, since the bag holds only the observed handshake fields.
func sshMetaOf(e Entry) SSHFingerprint {
	return SSHFingerprint{
		Hash:          e.Fingerprint,
		Raw:           metaString(e.Meta, "raw"),
		ClientID:      metaString(e.Meta, "client_id"),
		Kex:           metaString(e.Meta, "kex"),
		HostKey:       metaString(e.Meta, "host_key"),
		CipherC2S:     metaString(e.Meta, "cipher_c2s"),
		CipherS2C:     metaString(e.Meta, "cipher_s2c"),
		MACC2S:        metaString(e.Meta, "mac_c2s"),
		MACS2C:        metaString(e.Meta, "mac_s2c"),
		CompressC2S:   metaString(e.Meta, "compress_c2s"),
		CompressS2C:   metaString(e.Meta, "compress_s2c"),
		FirstKexGuess: metaBool(e.Meta, "first_kex_guess"),
	}
}

func metaString(meta map[string]any, key string) string {
	s, _ := meta[key].(string)
	return s
}

func metaBool(meta map[string]any, key string) bool {
	b, _ := meta[key].(bool)
	return b
}
