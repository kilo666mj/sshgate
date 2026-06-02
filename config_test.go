package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigAppliesDefaultCap(t *testing.T) {
	if cfg, err := loadConfig(""); err != nil || cfg.MaxFingerprints != defaultMaxFingerprints {
		t.Fatalf("empty path: cfg=%+v err=%v", cfg, err)
	}
	if cfg, err := loadConfig(filepath.Join(t.TempDir(), "missing.json")); err != nil || cfg.MaxFingerprints != defaultMaxFingerprints {
		t.Fatalf("missing file: cfg=%+v err=%v", cfg, err)
	}

	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"max_fingerprints": 0}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if cfg, err := loadConfig(path); err != nil || cfg.MaxFingerprints != defaultMaxFingerprints {
		t.Fatalf("zero in file should apply default: cfg=%+v err=%v", cfg, err)
	}

	if err := os.WriteFile(path, []byte(`{"max_fingerprints": -1}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if cfg, err := loadConfig(path); err != nil || cfg.MaxFingerprints != -1 {
		t.Fatalf("-1 should mean unlimited: cfg=%+v err=%v", cfg, err)
	}

	if err := os.WriteFile(path, []byte(`{"max_fingerprints": -5}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err == nil {
		t.Fatal("max_fingerprints < -1 should error")
	}
}
