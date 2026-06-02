package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	maxSSHLine   = 255
	maxSSHPacket = 256 * 1024
	// maxIdentBytes caps total bytes buffered while looking for the SSH
	// identification line. RFC 4253 allows preliminary lines before it; this
	// bounds a client that streams junk (or omits the SSH- banner) so a single
	// connection cannot exhaust memory before the read deadline fires.
	maxIdentBytes = 8 * 1024
	msgKexInit    = 20
)

type SSHFingerprint struct {
	Hash          string
	Raw           string
	ClientID      string
	Kex           string
	HostKey       string
	CipherC2S     string
	CipherS2C     string
	MACC2S        string
	MACS2C        string
	CompressC2S   string
	CompressS2C   string
	FirstKexGuess bool
}

type capturedClientHello struct {
	fingerprint SSHFingerprint
	bytes       []byte
}

type capturedIdentification struct {
	id    string
	bytes []byte
}

type capturedKexInit struct {
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

func readSSHIdentification(br *bufio.Reader) (capturedIdentification, error) {
	var captured []byte

	for {
		line, err := readSSHLine(br)
		if err != nil {
			return capturedIdentification{}, err
		}
		captured = append(captured, line...)
		if len(captured) > maxIdentBytes {
			return capturedIdentification{}, fmt.Errorf("SSH identification exceeded %d bytes", maxIdentBytes)
		}
		trimmed := strings.TrimRight(string(line), "\r\n")
		if strings.HasPrefix(trimmed, "SSH-") {
			return capturedIdentification{id: trimmed, bytes: captured}, nil
		}
	}
}

func readSSHKexInit(br *bufio.Reader, clientID string) (capturedKexInit, error) {
	packet, payload, err := readSSHPacket(br)
	if err != nil {
		return capturedKexInit{}, err
	}
	fp, err := parseKexInit(clientID, payload)
	if err != nil {
		return capturedKexInit{}, err
	}
	return capturedKexInit{fingerprint: fp, bytes: packet}, nil
}

func readSSHLine(r *bufio.Reader) ([]byte, error) {
	line := make([]byte, 0, 64)
	for {
		b, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		line = append(line, b)
		if b == '\n' {
			return line, nil
		}
		if len(line) >= maxSSHLine {
			return nil, fmt.Errorf("SSH identification line too long: >= %d bytes", maxSSHLine)
		}
	}
}

func readSSHPacket(r *bufio.Reader) ([]byte, []byte, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, nil, err
	}
	packetLen := binary.BigEndian.Uint32(header[:4])
	if packetLen < 2 || packetLen > maxSSHPacket {
		return nil, nil, fmt.Errorf("invalid SSH packet length: %d", packetLen)
	}
	paddingLen := int(header[4])
	if paddingLen < 4 || paddingLen >= int(packetLen) {
		return nil, nil, fmt.Errorf("invalid SSH padding length: %d", paddingLen)
	}

	rest := make([]byte, int(packetLen)-1)
	if _, err := io.ReadFull(r, rest); err != nil {
		return nil, nil, err
	}
	packet := append(header, rest...)
	payloadLen := int(packetLen) - paddingLen - 1
	if payloadLen < 1 {
		return nil, nil, errors.New("empty SSH packet payload")
	}
	return packet, rest[:payloadLen], nil
}

func parseKexInit(clientID string, payload []byte) (SSHFingerprint, error) {
	if len(payload) < 17 || payload[0] != msgKexInit {
		return SSHFingerprint{}, errors.New("first SSH packet is not SSH_MSG_KEXINIT")
	}
	p := payload[17:] // message byte + 16-byte cookie
	var lists [10]string
	for i := range lists {
		value, rest, err := readNameList(p)
		if err != nil {
			return SSHFingerprint{}, err
		}
		lists[i] = value
		p = rest
	}
	if len(p) < 5 {
		return SSHFingerprint{}, errors.New("truncated KEXINIT trailer")
	}

	raw := strings.Join([]string{
		lists[0],
		lists[1],
		lists[2],
		lists[3],
		lists[4],
		lists[5],
		lists[6],
		lists[7],
		boolString(p[0] != 0),
	}, ";")
	sum := sha256.Sum256([]byte(raw))
	return SSHFingerprint{
		Hash:          hex.EncodeToString(sum[:16]),
		Raw:           raw,
		ClientID:      clientID,
		Kex:           lists[0],
		HostKey:       lists[1],
		CipherC2S:     lists[2],
		CipherS2C:     lists[3],
		MACC2S:        lists[4],
		MACS2C:        lists[5],
		CompressC2S:   lists[6],
		CompressS2C:   lists[7],
		FirstKexGuess: p[0] != 0,
	}, nil
}

func readNameList(p []byte) (string, []byte, error) {
	if len(p) < 4 {
		return "", nil, errors.New("truncated name-list length")
	}
	n := int(binary.BigEndian.Uint32(p[:4]))
	p = p[4:]
	if n < 0 || n > len(p) {
		return "", nil, errors.New("truncated name-list")
	}
	return string(p[:n]), p[n:], nil
}

func boolString(v bool) string {
	if v {
		return "true"
	}
	return "false"
}
