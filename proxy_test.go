package main

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"

	gateproxy "github.com/kilo666mj/gatekit/proxy"
)

func testBanner(id string) *backendBanner {
	return &backendBanner{identification: capturedIdentification{id: id, bytes: []byte(id + "\r\n")}}
}

func TestRejectedClientNeverConnectsToBackend(t *testing.T) {
	for _, enrollment := range []bool{false, true} {
		t.Run(map[bool]string{false: "unknown", true: "explicitly-blocked-in-enrollment"}[enrollment], func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = ln.Close() }()
			st, err := NewStore(filepath.Join(t.TempDir(), "gate.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = st.Close() }()
			if enrollment {
				kex, err := readSSHKexInit(bufio.NewReader(bytes.NewReader(kexInitPacket())), "SSH-2.0-test")
				if err != nil {
					t.Fatal(err)
				}
				if err := st.UpsertStatus(kex.fingerprint.Hash, StatusBlocked, ""); err != nil {
					t.Fatal(err)
				}
			}
			client, peer := net.Pipe()
			defer func() { _ = peer.Close() }()
			done := make(chan struct{})
			go func() {
				defer close(done)
				handleConn(client, gateproxy.Route{Backend: ln.Addr().String()}, st, enrollment, nil, testBanner("SSH-2.0-test-server"))
			}()
			if err := peer.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := peer.Write([]byte("SSH-2.0-test\r\n")); err != nil {
				t.Fatal(err)
			}
			r := bufio.NewReader(peer)
			if _, err := r.ReadString('\n'); err != nil {
				t.Fatal(err)
			}
			if _, err := peer.Write(kexInitPacket()); err != nil {
				t.Fatal(err)
			}
			if _, err := r.ReadByte(); err != io.EOF {
				t.Fatalf("expected rejection, got %v", err)
			}
			<-done
			if err := ln.(*net.TCPListener).SetDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			conn, err := ln.Accept()
			if err == nil {
				_ = conn.Close()
				t.Fatal("rejected client opened a backend connection")
			}
			if !isTimeout(err) {
				t.Fatal(err)
			}
		})
	}
}

func TestApprovedClientChecksBannerAndPreservesBufferedTraffic(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	st, err := NewStore(filepath.Join(t.TempDir(), "gate.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	packet := kexInitPacket()
	kex, err := readSSHKexInit(bufio.NewReader(bytes.NewReader(packet)), "SSH-2.0-test")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertStatus(kex.fingerprint.Hash, StatusApproved, ""); err != nil {
		t.Fatal(err)
	}
	banner := testBanner("SSH-2.0-old-server")
	for attempt := 0; attempt < 2; attempt++ {
		backendResult := make(chan error, 1)
		go func() {
			c, err := ln.Accept()
			if err != nil {
				backendResult <- err
				return
			}
			defer func() { _ = c.Close() }()
			_ = c.SetDeadline(time.Now().Add(3 * time.Second))
			r := bufio.NewReader(c)
			if _, err := r.ReadString('\n'); err != nil {
				backendResult <- err
				return
			}
			if _, err := c.Write([]byte("SSH-2.0-new-server\r\nserver-data")); err != nil {
				backendResult <- err
				return
			}
			if attempt == 0 {
				_, err := r.ReadByte()
				if err == io.EOF {
					err = nil
				}
				backendResult <- err
				return
			}
			got := make([]byte, len(packet))
			_, err = io.ReadFull(r, got)
			if err == nil && !bytes.Equal(got, packet) {
				err = io.ErrUnexpectedEOF
			}
			backendResult <- err
		}()
		client, peer := net.Pipe()
		done := make(chan struct{})
		go func() {
			defer close(done)
			handleConn(client, gateproxy.Route{Backend: ln.Addr().String()}, st, false, nil, banner)
		}()
		_ = peer.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := peer.Write([]byte("SSH-2.0-test\r\n")); err != nil {
			t.Fatal(err)
		}
		r := bufio.NewReader(peer)
		if _, err := r.ReadString('\n'); err != nil {
			t.Fatal(err)
		}
		if _, err := peer.Write(packet); err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(r)
		_ = peer.Close()
		<-done
		if err != nil {
			t.Fatal(err)
		}
		want := ""
		if attempt == 1 {
			want = "server-data"
		}
		if string(got) != want {
			t.Fatalf("attempt %d: got %q, want %q", attempt, got, want)
		}
		if err := <-backendResult; err != nil {
			t.Fatal(err)
		}
		if banner.get().id != "SSH-2.0-new-server" {
			t.Fatal("banner was not refreshed")
		}
	}
}
