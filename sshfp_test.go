package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"strings"
	"testing"
)

// capturedClientHello and readSSHClientHello are test helpers: they read a
// full client identification + KEXINIT from a single stream. Production code
// reads the two phases separately (see handleConn) so it can relay the server
// identification before waiting for client KEXINIT.
type capturedClientHello struct {
	fingerprint SSHFingerprint
	bytes       []byte
}

func readSSHClientHello(r io.Reader) (capturedClientHello, error) {
	br := bufio.NewReader(r)
	ident, err := readSSHIdentification(br)
	if err != nil {
		return capturedClientHello{}, err
	}
	kex, err := readSSHKexInit(br, ident.id)
	if err != nil {
		return capturedClientHello{}, err
	}
	return capturedClientHello{
		fingerprint: kex.fingerprint,
		bytes:       append(ident.bytes, kex.bytes...),
	}, nil
}

func TestReadSSHClientHelloComputesStableKexFingerprint(t *testing.T) {
	raw := strings.Join([]string{
		"curve25519-sha256,diffie-hellman-group14-sha256",
		"ssh-ed25519,rsa-sha2-512",
		"chacha20-poly1305@openssh.com,aes128-ctr",
		"chacha20-poly1305@openssh.com,aes128-ctr",
		"hmac-sha2-256",
		"hmac-sha2-256",
		"none,zlib@openssh.com",
		"none,zlib@openssh.com",
		"false",
	}, ";")
	sum := sha256.Sum256([]byte(raw))
	want := hex.EncodeToString(sum[:16])

	hello, err := readSSHClientHello(bytes.NewReader(append([]byte("SSH-2.0-OpenSSH_9.7\r\n"), kexInitPacket()...)))
	if err != nil {
		t.Fatalf("readSSHClientHello() error = %v", err)
	}
	if hello.fingerprint.Hash != want {
		t.Fatalf("hash = %s, want %s", hello.fingerprint.Hash, want)
	}
	if hello.fingerprint.ClientID != "SSH-2.0-OpenSSH_9.7" {
		t.Fatalf("client id = %q", hello.fingerprint.ClientID)
	}
	if hello.fingerprint.HostKey != "ssh-ed25519,rsa-sha2-512" {
		t.Fatalf("host key algorithms = %q", hello.fingerprint.HostKey)
	}
	if len(hello.bytes) == 0 {
		t.Fatal("captured bytes are empty")
	}
}

func TestFingerprintIgnoresClientIdentification(t *testing.T) {
	packet := kexInitPacket()
	first, err := readSSHClientHello(bytes.NewReader(append([]byte("SSH-2.0-OpenSSH_10.0p2 Debian-7+deb13u4\r\n"), packet...)))
	if err != nil {
		t.Fatalf("read first hello: %v", err)
	}
	second, err := readSSHClientHello(bytes.NewReader(append([]byte("SSH-2.0-OpenSSH_10.3\r\n"), packet...)))
	if err != nil {
		t.Fatalf("read second hello: %v", err)
	}
	if first.fingerprint.Hash != second.fingerprint.Hash {
		t.Fatalf("fingerprints should match when only client IDs differ: %s != %s", first.fingerprint.Hash, second.fingerprint.Hash)
	}
}

func kexInitPacket() []byte {
	var payload []byte
	payload = append(payload, msgKexInit)
	payload = append(payload, make([]byte, 16)...)
	for _, list := range []string{
		"curve25519-sha256,diffie-hellman-group14-sha256",
		"ssh-ed25519,rsa-sha2-512",
		"chacha20-poly1305@openssh.com,aes128-ctr",
		"chacha20-poly1305@openssh.com,aes128-ctr",
		"hmac-sha2-256",
		"hmac-sha2-256",
		"none,zlib@openssh.com",
		"none,zlib@openssh.com",
		"",
		"",
	} {
		payload = appendNameList(payload, list)
	}
	payload = append(payload, 0)
	payload = binary.BigEndian.AppendUint32(payload, 0)

	paddingLen := byte(8)
	packetLen := uint32(1 + len(payload) + int(paddingLen))
	var packet []byte
	packet = binary.BigEndian.AppendUint32(packet, packetLen)
	packet = append(packet, paddingLen)
	packet = append(packet, payload...)
	packet = append(packet, make([]byte, paddingLen)...)
	return packet
}

func appendNameList(dst []byte, value string) []byte {
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(value)))
	dst = append(dst, value...)
	return dst
}

func TestReadSSHIdentificationRejectsFlood(t *testing.T) {
	var junk []byte
	for len(junk) <= maxIdentBytes {
		junk = append(junk, []byte("not-the-banner\r\n")...)
	}
	if _, err := readSSHClientHello(bytes.NewReader(junk)); err == nil {
		t.Fatal("expected error when identification exceeds the byte cap")
	}
}

func TestReadSSHLineRejectsUnterminatedLine(t *testing.T) {
	long := bytes.Repeat([]byte("A"), maxSSHLine+10) // no newline
	if _, err := readSSHClientHello(bytes.NewReader(long)); err == nil {
		t.Fatal("expected error for over-long unterminated line")
	}
}

func TestOversizedKexRejectedBeforeReadingBody(t *testing.T) {
	header := binary.BigEndian.AppendUint32(nil, maxSSHPacket+1)
	header = append(header, 8)
	if _, _, err := readSSHPacket(bufio.NewReader(bytes.NewReader(header))); err == nil || !strings.Contains(err.Error(), "invalid SSH packet length") {
		t.Fatalf("oversized packet was not rejected from its header: %v", err)
	}
}
