package main

import (
	"path/filepath"
	"testing"
)

func TestStoreObserveDefaultsToPendingAndTracksIPs(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "sshgate.db"))
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	fp := SSHFingerprint{Hash: "abc123", ClientID: "SSH-2.0-test", Raw: "a;b;c;d"}
	entry, err := store.Observe(fp, "203.0.113.10", false)
	if err != nil {
		t.Fatalf("Observe() error = %v", err)
	}
	if entry.Status != StatusPending {
		t.Fatalf("status = %q, want %q", entry.Status, StatusPending)
	}
	if err := store.SetStatus("abc123", StatusApproved, "laptop"); err != nil {
		t.Fatalf("SetStatus() error = %v", err)
	}
	entry, err = store.Observe(fp, "203.0.113.11", false)
	if err != nil {
		t.Fatalf("Observe() error = %v", err)
	}
	if entry.Status != StatusApproved || entry.Label != "laptop" {
		t.Fatalf("entry = %+v", entry)
	}
	if len(entry.IPs) != 2 {
		t.Fatalf("IPs = %v, want two", entry.IPs)
	}
}

func TestStoreUpsertStatusPreApprovesUnobservedFingerprint(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "sshgate.db"))
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}

	const hash = "abc123"
	if err := store.UpsertStatus(hash, StatusApproved, "ci-runner"); err != nil {
		t.Fatalf("UpsertStatus() error = %v", err)
	}

	// First connection keeps the pre-approved status and fills in metadata.
	fp := SSHFingerprint{Hash: hash, ClientID: "SSH-2.0-test", Raw: "a;b;c;d", Kex: "curve25519"}
	entry, err := store.Observe(fp, "203.0.113.10", true)
	if err != nil {
		t.Fatalf("Observe() error = %v", err)
	}
	if entry.Status != StatusApproved {
		t.Fatalf("status = %q, want %q", entry.Status, StatusApproved)
	}
	if entry.Label != "ci-runner" {
		t.Fatalf("label = %q, want %q", entry.Label, "ci-runner")
	}
	if entry.Raw != "a;b;c;d" || entry.Kex != "curve25519" {
		t.Fatalf("metadata not filled: %+v", entry)
	}
	if len(entry.IPs) != 1 {
		t.Fatalf("IPs = %v, want one", entry.IPs)
	}
}

func TestStoreUpsertStatusUpdatesExistingAndKeepsLabel(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "sshgate.db"))
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}

	const hash = "abc123"
	if err := store.UpsertStatus(hash, StatusApproved, "ci-runner"); err != nil {
		t.Fatalf("UpsertStatus() initial error = %v", err)
	}
	// Re-running with an empty label must change status but preserve the label.
	if err := store.UpsertStatus(hash, StatusBlocked, ""); err != nil {
		t.Fatalf("UpsertStatus() update error = %v", err)
	}

	entries, err := store.List()
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	entry := entries[hash]
	if entry.Status != StatusBlocked {
		t.Fatalf("status = %q, want %q", entry.Status, StatusBlocked)
	}
	if entry.Label != "ci-runner" {
		t.Fatalf("label = %q, want %q", entry.Label, "ci-runner")
	}
}

func TestStoreReloadsExternalStatusChanges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sshgate.db")
	daemonStore, err := NewStore(path)
	if err != nil {
		t.Fatalf("NewStore daemon: %v", err)
	}
	fp := SSHFingerprint{Hash: "abc123", ClientID: "SSH-2.0-test", Raw: "a;b;c;d"}
	entry, err := daemonStore.Observe(fp, "203.0.113.10", false)
	if err != nil {
		t.Fatalf("Observe initial: %v", err)
	}
	if entry.Status != StatusPending {
		t.Fatalf("initial status = %q, want %q", entry.Status, StatusPending)
	}

	cliStore, err := NewStore(path)
	if err != nil {
		t.Fatalf("NewStore cli: %v", err)
	}
	if err := cliStore.SetStatus("abc123", StatusApproved, "laptop"); err != nil {
		t.Fatalf("SetStatus: %v", err)
	}

	entry, err = daemonStore.Observe(fp, "203.0.113.10", false)
	if err != nil {
		t.Fatalf("Observe after approval: %v", err)
	}
	if entry.Status != StatusApproved {
		t.Fatalf("status after external approval = %q, want %q", entry.Status, StatusApproved)
	}
}

func TestStorePruneToLimitPreservesApproved(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "sshgate.db"))
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	for _, fp := range []SSHFingerprint{
		{Hash: "old-pending", ClientID: "SSH-2.0-test", Raw: "a;b;c;d"},
		{Hash: "approved", ClientID: "SSH-2.0-test", Raw: "a;b;c;d"},
		{Hash: "new-pending", ClientID: "SSH-2.0-test", Raw: "a;b;c;d"},
	} {
		if _, err := store.Observe(fp, "203.0.113.10", false); err != nil {
			t.Fatalf("Observe(%s): %v", fp.Hash, err)
		}
	}
	if err := store.SetStatus("approved", StatusApproved, "laptop"); err != nil {
		t.Fatalf("SetStatus approved: %v", err)
	}

	n, err := store.PruneToLimit(2)
	if err != nil {
		t.Fatalf("PruneToLimit: %v", err)
	}
	if n != 1 {
		t.Fatalf("pruned = %d, want 1", n)
	}
	entries, err := store.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if _, ok := entries["approved"]; !ok {
		t.Fatal("approved fingerprint was pruned")
	}
	if len(entries) != 2 {
		t.Fatalf("entries = %v, want 2", entries)
	}
}

func TestStoreObserveBlocksUnknownWhenConfigured(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "sshgate.db"))
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	fp := SSHFingerprint{Hash: "abc123", ClientID: "SSH-2.0-test", Raw: "a;b;c;d"}
	entry, err := store.Observe(fp, "203.0.113.10", true)
	if err != nil {
		t.Fatalf("Observe() error = %v", err)
	}
	if entry.Status != StatusBlocked {
		t.Fatalf("status = %q, want %q", entry.Status, StatusBlocked)
	}
}
