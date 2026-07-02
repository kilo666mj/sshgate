package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
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

func TestLoadConfigParsesControlPlane(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	data := `{
		"max_fingerprints": 100,
		"control_plane": {
			"url": "https://gatehub.example.com/base",
			"instance_id": "public-ssh",
			"client_cert": "/etc/gatehub/client.crt",
			"client_key": "/etc/gatehub/client.key",
			"ca": "/etc/gatehub/ca.crt",
			"server_name": "gatehub.example.com",
			"sync_interval": "45s"
		}
	}`
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.ControlPlane.InstanceID != "public-ssh" || cfg.ControlPlane.interval() != 45*time.Second {
		t.Fatalf("control plane config = %+v", cfg.ControlPlane)
	}
	u, err := controlPlaneURL(cfg.ControlPlane.URL, "/v1/policy", cfg.ControlPlane.InstanceID, "cursor")
	if err != nil {
		t.Fatalf("controlPlaneURL: %v", err)
	}
	if want := "https://gatehub.example.com/base/v1/policy?instance_id=public-ssh&since=cursor"; u != want {
		t.Fatalf("controlPlaneURL = %q, want %q", u, want)
	}
}
