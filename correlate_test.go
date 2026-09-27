package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kilo666mj/gatekit/store"
)

const testFP = "aaf62b02afeaa8df0687aa49b07825f8"

func writeLog(t *testing.T, name string, lines ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func testEntry(t *testing.T, first, last string, ips ...string) Entry {
	t.Helper()
	parse := func(s string) store.Time {
		v, err := time.Parse(time.RFC3339, s)
		if err != nil {
			t.Fatal(err)
		}
		return store.Time{Time: v}
	}
	return Entry{Fingerprint: testFP, FirstSeen: parse(first), LastSeen: parse(last), IPs: ips}
}

// Lines as sshd and sshgate write them on a host where sshd listens only on
// 127.0.0.1:22 behind sshgate (RFC 3339 rsyslog format, as on Debian 13).
func TestCorrelateJoinsGatedSessionsOnBackendPort(t *testing.T) {
	gateLog := writeLog(t, "syslog",
		"2026-09-27T10:20:14.100000+02:00 mx sshgate[3348374]: 2026/09/27 10:20:14 [203.0.113.160] CONNECTED "+testFP+" backend=127.0.0.1:22 local=127.0.0.1:40732",
		// Another client's connection must not be attributed to this fingerprint.
		"2026-09-27T10:20:30.100000+02:00 mx sshgate[3348374]: 2026/09/27 10:20:30 [198.51.100.9] CONNECTED 1111111111111111111111111111111f backend=127.0.0.1:22 local=127.0.0.1:40800",
	)
	authLog := writeLog(t, "auth.log",
		"2026-09-27T10:20:14.300000+02:00 mx sshd-session[3349342]: Accepted publickey for michael from 127.0.0.1 port 40732 ssh2: RSA SHA256:dy7FV",
		"2026-09-27T10:20:30.300000+02:00 mx sshd-session[3349400]: Accepted publickey for other from 127.0.0.1 port 40800 ssh2: RSA SHA256:zzz",
		// Port 40732 reused much later by a connection with no CONNECTED line.
		"2026-09-27T11:45:00.000000+02:00 mx sshd-session[3349999]: Accepted publickey for root from 127.0.0.1 port 40732 ssh2: RSA SHA256:yyy",
	)
	entry := testEntry(t, "2026-09-27T08:00:00Z", "2026-09-27T08:20:14Z", "203.0.113.160")

	gates, err := readGateConnects(gateLog, testFP, entry.LastSeen.Time)
	if err != nil {
		t.Fatal(err)
	}
	if len(gates) != 1 || gates[0].port != 40732 || gates[0].ip != "203.0.113.160" || gates[0].host != "mx" {
		t.Fatalf("gates = %+v", gates)
	}
	matches, err := correlateSSHDLog(authLog, entry, 2*time.Minute, 100, gates, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 {
		t.Fatalf("matches = %+v", matches)
	}
	m := matches[0]
	if m.ip != "203.0.113.160" || m.source != "gate:40732" || m.user != "michael" {
		t.Fatalf("match = %+v", m)
	}
}

func TestCorrelateGateJoinRequiresSameHost(t *testing.T) {
	gates := []gateConnect{{when: time.Date(2026, 9, 27, 8, 20, 14, 0, time.UTC), host: "snuffles", ip: "203.0.113.160", port: 40732}}
	authLog := writeLog(t, "auth.log",
		"2026-09-27T10:20:14.300000+02:00 mx sshd[1]: Accepted publickey for michael from 127.0.0.1 port 40732 ssh2",
	)
	entry := testEntry(t, "2026-09-27T08:00:00Z", "2026-09-27T08:20:14Z", "203.0.113.160")
	matches, err := correlateSSHDLog(authLog, entry, 2*time.Minute, 100, gates, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("joined across hosts: %+v", matches)
	}
}

func TestCorrelateDirectConnectionsStillMatchByIP(t *testing.T) {
	authLog := writeLog(t, "auth.log",
		// Classic syslog format, and the older sshd process name.
		"Sep 27 10:20:14 mx sshd[1234]: Failed password for invalid user admin from 203.0.113.160 port 5555 ssh2",
		"Sep 27 10:21:00 mx sshd[1234]: Accepted publickey for michael from 198.51.100.1 port 5556 ssh2",
		// Outside the window around first/last seen.
		"Sep 27 16:00:00 mx sshd[1234]: Accepted publickey for michael from 203.0.113.160 port 5557 ssh2",
	)
	local := time.Date(2026, 9, 27, 10, 20, 0, 0, time.Local)
	entry := Entry{Fingerprint: testFP, FirstSeen: store.Time{Time: local}, LastSeen: store.Time{Time: local}, IPs: []string{"203.0.113.160"}}
	matches, err := correlateSSHDLog(authLog, entry, 2*time.Minute, 100, nil, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 || matches[0].source != "direct" || matches[0].ip != "203.0.113.160" || matches[0].user != "admin" {
		t.Fatalf("matches = %+v", matches)
	}
}

func TestMatchGateConnectPicksNearestWithinWindow(t *testing.T) {
	at := time.Date(2026, 9, 27, 8, 0, 0, 0, time.UTC)
	gates := []gateConnect{
		{when: at.Add(-8 * time.Second), host: "mx", ip: "198.51.100.1", port: 40000},
		{when: at.Add(-1 * time.Second), host: "mx", ip: "198.51.100.2", port: 40000},
		{when: at.Add(-30 * time.Second), host: "mx", ip: "198.51.100.3", port: 40000},
	}
	g, ok := matchGateConnect(gates, "mx", 40000, at, 10*time.Second)
	if !ok || g.ip != "198.51.100.2" {
		t.Fatalf("got %+v %v", g, ok)
	}
	if _, ok := matchGateConnect(gates[2:], "mx", 40000, at, 10*time.Second); ok {
		t.Fatal("matched a connection outside the join window")
	}
}

func TestIsUsefulSSHDLogAcceptsSSHDSession(t *testing.T) {
	if !isUsefulSSHDLog("2026-09-27T10:20:14+02:00 mx sshd-session[1]: Accepted publickey for michael from 127.0.0.1 port 1 ssh2") {
		t.Fatal("sshd-session line rejected")
	}
}
