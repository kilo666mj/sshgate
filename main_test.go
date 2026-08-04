package main

import (
	"path/filepath"
	"testing"

	"github.com/kilo666mj/gatekit/store"
)

// Re-approving a labelled fingerprint without repeating --label used to blank
// the label: cmdSetStatus passed the empty flag value straight into a
// SetStatus that wrote both columns. Status and label are now separate
// operations, and the label is only written when one was actually given.
func TestSetStatusWithoutLabelKeepsExistingLabel(t *testing.T) {
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
	st.Close()

	// approve --label michael-laptop <fp>
	cmdSetStatus([]string{"--db", path, "--label", "michael-laptop", fp.Hash}, StatusApproved)
	// block <fp>  — no --label, so the existing one must survive
	cmdSetStatus([]string{"--db", path, fp.Hash}, StatusBlocked)

	st, err = NewStore(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer st.Close()
	entry, err := st.Get(fp.Hash)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if entry.Status != StatusBlocked {
		t.Errorf("status = %q, want blocked", entry.Status)
	}
	if entry.Label != "michael-laptop" {
		t.Errorf("label = %q, want it preserved when --label is omitted", entry.Label)
	}
}

// Passing --label must still replace the label.
func TestSetStatusWithLabelReplacesIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sshgate.db")
	st, err := NewStore(path)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	fp := testFingerprint()
	if _, err := st.Observe(store.Observation{Fingerprint: fp.Hash, IP: "192.0.2.10"}, false); err != nil {
		t.Fatalf("Observe: %v", err)
	}
	st.Close()

	cmdSetStatus([]string{"--db", path, "--label", "first", fp.Hash}, StatusApproved)
	cmdSetStatus([]string{"--db", path, "--label", "second", fp.Hash}, StatusApproved)

	st, err = NewStore(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer st.Close()
	entry, err := st.Get(fp.Hash)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if entry.Label != "second" {
		t.Errorf("label = %q, want second", entry.Label)
	}
}
