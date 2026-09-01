package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestDoctorReportsDefaultsWithoutCreatingFiles(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "missing.db")
	configPath := filepath.Join(dir, "missing.json")
	var out bytes.Buffer

	err := runDoctor([]string{
		"--db", dbPath,
		"--config", configPath,
		"--allow-unknown",
		"--route", "[::]:2222=127.0.0.1:22",
	}, &out)
	if err != nil {
		t.Fatalf("runDoctor: %v", err)
	}
	for _, want := range []string{
		"database: " + dbPath + " (not created yet)",
		"config: " + configPath + " (absent; built-in defaults apply)",
		"max fingerprints: 100000",
		"control plane: disabled",
		"unknown fingerprints: allowed as pending (enrollment mode)",
		"route: [::]:2222 -> 127.0.0.1:22",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output missing %q:\n%s", want, out.String())
		}
	}
	if _, err := os.Stat(dbPath); !os.IsNotExist(err) {
		t.Fatalf("doctor created database: %v", err)
	}
}

func TestDoctorRejectsInvalidConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"max_fingerprints":-2}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runDoctor([]string{"--config", path}, &out); err == nil {
		t.Fatal("runDoctor accepted invalid config")
	}
}

func TestDoctorReportsOutputFailure(t *testing.T) {
	err := runDoctor([]string{"--db", filepath.Join(t.TempDir(), "missing.db")}, failingWriter{})
	if !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("runDoctor error = %v, want closed pipe", err)
	}
}
