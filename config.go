package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/kilo666mj/gatekit/controlplane"
	"os"
)

const (
	defaultConfig = "/etc/sshgate/config.json"
	// defaultMaxFingerprints is applied when max_fingerprints is unset (0). It
	// bounds disk growth from randomized KEXINIT material by default; set -1 to
	// opt into unlimited storage.
	defaultMaxFingerprints = 100000
)

type AppConfig struct {
	// MaxFingerprints caps stored fingerprint entries. 0 applies
	// defaultMaxFingerprints; -1 means unlimited. Approved entries are never
	// evicted; oldest non-approved entries are pruned first.
	MaxFingerprints int                 `json:"max_fingerprints"`
	ControlPlane    controlplane.Config `json:"control_plane"`
}

func loadConfig(path string) (AppConfig, error) {
	if path == "" {
		return AppConfig{MaxFingerprints: defaultMaxFingerprints}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return AppConfig{MaxFingerprints: defaultMaxFingerprints}, nil
		}
		return AppConfig{}, err
	}
	var cfg AppConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return AppConfig{}, err
	}
	if cfg.MaxFingerprints < -1 {
		return AppConfig{}, fmt.Errorf("max_fingerprints must be >= -1, got %d", cfg.MaxFingerprints)
	}
	if cfg.MaxFingerprints == 0 {
		cfg.MaxFingerprints = defaultMaxFingerprints
	}
	return cfg, nil
}
