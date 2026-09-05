package main

import (
	"bufio"
	"net"
	"sync"
	"time"
)

// backendBanner holds the immutable identification last read from the trusted
// backend. Only an allowed connection can refresh it. Comparing identifications
// before forwarding KEXINIT preserves the version strings in SSH's exchange hash.
type backendBanner struct {
	mu             sync.RWMutex
	identification capturedIdentification
}

func (b *backendBanner) get() capturedIdentification {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.identification
}

func (b *backendBanner) set(id capturedIdentification) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.identification = id
}

// Probe once per route at startup, rather than once per untrusted connection.
func loadBackendBanner(address string) (*backendBanner, error) {
	conn, err := net.DialTimeout("tcp", address, handshakeTimeout)
	if err != nil {
		return nil, err
	}
	defer closeConnection(conn, "startup", "backend")
	if err := conn.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		return nil, err
	}
	if _, err := conn.Write([]byte("SSH-2.0-SSHGate_banner_probe\r\n")); err != nil {
		return nil, err
	}
	id, err := readSSHIdentification(bufio.NewReader(conn))
	if err != nil {
		return nil, err
	}
	return &backendBanner{identification: id}, nil
}
