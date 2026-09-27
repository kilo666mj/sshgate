package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
)

const (
	defaultAuthLog = "/var/log/auth.log"
	// sshgate logs to the journal; rsyslog copies it to syslog on Debian.
	defaultGateLog = "/var/log/syslog"
)

type logMatch struct {
	when   time.Time
	ip     string
	source string
	user   string
	line   string
}

// gateConnect is one sshgate CONNECTED line: the client address and the local
// port of the backend socket, which is the port sshd logs for the session.
type gateConnect struct {
	when time.Time
	host string
	ip   string
	port int
}

var (
	gateConnectRE = regexp.MustCompile(`\[([^\]]+)\] CONNECTED (\S+) backend=\S+ local=(\S+)`)
	sshdSourceRE  = regexp.MustCompile(`from (\S+) port (\d+)`)
)

func cmdCorrelate(args []string) {
	fs := flag.NewFlagSet("correlate", flag.ExitOnError)
	dbPath := fs.String("db", defaultDB, "database path")
	logPath := fs.String("log", defaultAuthLog, "sshd log path")
	gateLog := fs.String("gate-log", defaultGateLog, "log with sshgate CONNECTED lines, used to attribute sessions sshd logs as loopback")
	window := fs.Duration("window", 2*time.Minute, "time window around first/last seen for direct connections")
	joinWindow := fs.Duration("join-window", 10*time.Second, "maximum time between an sshgate CONNECTED line and the sshd line joined to it")
	limit := fs.Int("limit", 100, "maximum matches to print")
	if err := fs.Parse(args); err != nil {
		fatalf("parse correlate options: %v", err)
	}
	if fs.NArg() != 1 {
		fatalf("usage: correlate [--log <path>] [--gate-log <path>] [--window <duration>] <fingerprint>")
	}

	st, err := NewStore(*dbPath)
	if err != nil {
		fatalf("open store: %v", err)
	}
	fp, err := st.ResolveFingerprint(fs.Arg(0))
	if err != nil {
		fatalf("%v", err)
	}
	entry, err := st.Get(fp)
	if err != nil {
		fatalf("load fingerprint: %v", err)
	}
	if len(entry.IPs) == 0 {
		fatalf("fingerprint %s has no IPs to correlate", fp)
	}

	gates, err := readGateConnects(*gateLog, fp, entry.LastSeen.Time)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			fatalf("read sshgate log: %v", err)
		}
		fmt.Fprintf(os.Stderr, "warning: %v; sessions sshd logs as loopback cannot be attributed\n", err)
	}
	matches, err := correlateSSHDLog(*logPath, entry, *window, *limit, gates, *joinWindow)
	if err != nil {
		fatalf("correlate sshd log: %v", err)
	}

	fmt.Printf("fingerprint: %s\n", fp)
	if entry.Label != "" {
		fmt.Printf("label: %s\n", entry.Label)
	}
	fmt.Printf("window: +/- %s around first_seen=%s and last_seen=%s (direct connections)\n",
		window.String(), formatTime(entry.FirstSeen), formatTime(entry.LastSeen))
	fmt.Printf("gated sessions: %d CONNECTED line(s) in %s\n", len(gates), *gateLog)
	if len(matches) == 0 {
		fmt.Println("no matching sshd log lines found")
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	writeOrFatal(w, "TIME\tIP\tSOURCE\tUSER\tLINE\n")
	for _, m := range matches {
		writeOrFatal(w, "%s\t%s\t%s\t%s\t%s\n",
			m.when.Format("2006-01-02 15:04:05"),
			m.ip,
			m.source,
			valueOrDash(sanitizeDisplay(m.user)),
			sanitizeDisplay(m.line),
		)
	}
	flushOrFatal(w)
}

// correlateSSHDLog reports sshd lines for the fingerprint's sessions. When
// sshd listens behind sshgate it logs every client as loopback, so those
// lines are joined to the gate's CONNECTED line for the same host and port;
// lines from a real client address are matched against the fingerprint's
// known IPs near its first/last seen times.
func correlateSSHDLog(path string, entry Entry, window time.Duration, limit int, gates []gateConnect, joinWindow time.Duration) (_ []logMatch, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := f.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close sshd log: %w", closeErr))
		}
	}()

	ips := make([]string, len(entry.IPs))
	copy(ips, entry.IPs)
	sort.Strings(ips)

	var matches []logMatch
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if !isUsefulSSHDLog(line) {
			continue
		}
		when, ok := parseLogTime(line, entry.LastSeen.Time)
		if !ok {
			continue
		}
		m := logMatch{when: when, user: extractSSHUser(line), line: line}
		if src, port, ok := sshdSource(line); ok && isLoopbackAddr(src) {
			g, ok := matchGateConnect(gates, logHost(line), port, when, joinWindow)
			if !ok {
				continue
			}
			m.ip, m.source = g.ip, fmt.Sprintf("gate:%d", port)
		} else {
			ip, ok := lineContainsAnyIP(line, ips)
			if !ok || !withinCorrelationWindows(when, entry, window) {
				continue
			}
			m.ip, m.source = ip, "direct"
		}
		matches = append(matches, m)
		if limit > 0 && len(matches) >= limit {
			break
		}
	}
	return matches, scanner.Err()
}

// readGateConnects returns the CONNECTED lines logged for fingerprint.
func readGateConnects(path, fingerprint string, ref time.Time) (_ []gateConnect, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := f.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close sshgate log: %w", closeErr))
		}
	}()
	var gates []gateConnect
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, " CONNECTED "+fingerprint+" ") {
			continue
		}
		m := gateConnectRE.FindStringSubmatch(line)
		if m == nil || m[2] != fingerprint {
			continue
		}
		_, portText, err := net.SplitHostPort(m[3])
		if err != nil {
			continue
		}
		port, err := strconv.Atoi(portText)
		if err != nil {
			continue
		}
		when, ok := parseLogTime(line, ref)
		if !ok {
			continue
		}
		gates = append(gates, gateConnect{when: when, host: logHost(line), ip: m[1], port: port})
	}
	return gates, scanner.Err()
}

// matchGateConnect returns the CONNECTED line closest in time to an sshd line
// with the same host and port. Local ports are reused, so only lines within
// joinWindow count.
func matchGateConnect(gates []gateConnect, host string, port int, when time.Time, joinWindow time.Duration) (gateConnect, bool) {
	var (
		best  gateConnect
		found bool
		gap   time.Duration
	)
	for _, g := range gates {
		if g.port != port || (host != "" && g.host != "" && g.host != host) {
			continue
		}
		d := when.Sub(g.when)
		if d < 0 {
			d = -d
		}
		if d > joinWindow || (found && d >= gap) {
			continue
		}
		best, found, gap = g, true, d
	}
	return best, found
}

// sshdSource returns the address and port from an sshd "from <ip> port <n>"
// clause.
func sshdSource(line string) (string, int, bool) {
	m := sshdSourceRE.FindStringSubmatch(line)
	if m == nil {
		return "", 0, false
	}
	port, err := strconv.Atoi(m[2])
	if err != nil {
		return "", 0, false
	}
	return m[1], port, true
}

func isLoopbackAddr(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.IsLoopback()
}

// logHost returns the host field of an RFC 3339 or classic syslog line.
func logHost(line string) string {
	fields := strings.Fields(line)
	if len(fields) > 1 {
		if _, err := time.Parse(time.RFC3339Nano, fields[0]); err == nil {
			return fields[1]
		}
	}
	if len(fields) > 3 {
		return fields[3]
	}
	return ""
}

func isUsefulSSHDLog(line string) bool {
	lower := strings.ToLower(line)
	return strings.Contains(lower, "sshd") &&
		(strings.Contains(lower, "accepted ") ||
			strings.Contains(lower, "failed ") ||
			strings.Contains(lower, "invalid user") ||
			strings.Contains(lower, "userauth"))
}

// lineContainsAnyIP returns the first IP in ips (pre-sorted by the caller for
// deterministic matches) that appears in line.
func lineContainsAnyIP(line string, ips []string) (string, bool) {
	for _, ip := range ips {
		if strings.Contains(line, ip) {
			return ip, true
		}
	}
	return "", false
}

func parseLogTime(line string, ref time.Time) (time.Time, bool) {
	if fields := strings.Fields(line); len(fields) > 0 {
		if when, err := time.Parse(time.RFC3339Nano, fields[0]); err == nil {
			return when, true
		}
	}
	if len(line) < len("Jan  2 15:04:05") {
		return time.Time{}, false
	}
	prefix := line[:len("Jan  2 15:04:05")]
	parsed, err := time.ParseInLocation("Jan _2 15:04:05", prefix, ref.Location())
	if err != nil {
		return time.Time{}, false
	}
	when := time.Date(ref.Year(), parsed.Month(), parsed.Day(), parsed.Hour(), parsed.Minute(), parsed.Second(), 0, ref.Location())
	if when.After(ref.AddDate(0, 6, 0)) {
		when = when.AddDate(-1, 0, 0)
	} else if when.Before(ref.AddDate(0, -6, 0)) {
		when = when.AddDate(1, 0, 0)
	}
	return when, true
}

func withinCorrelationWindows(t time.Time, entry Entry, window time.Duration) bool {
	return withinWindow(t, entry.FirstSeen.Time, window) || withinWindow(t, entry.LastSeen.Time, window)
}

func withinWindow(t, center time.Time, window time.Duration) bool {
	if center.IsZero() {
		return false
	}
	return !t.Before(center.Add(-window)) && !t.After(center.Add(window))
}

func extractSSHUser(line string) string {
	fields := strings.Fields(line)
	for i, field := range fields {
		switch field {
		case "for":
			if i+1 < len(fields) && fields[i+1] != "invalid" {
				return strings.Trim(fields[i+1], " ,")
			}
			// "for invalid user <name>" (OpenSSH) or "for invalid <name>".
			if i+3 < len(fields) && fields[i+1] == "invalid" && fields[i+2] == "user" {
				return strings.Trim(fields[i+3], " ,")
			}
			if i+2 < len(fields) && fields[i+1] == "invalid" {
				return strings.Trim(fields[i+2], " ,")
			}
		case "user":
			if i+1 < len(fields) {
				return strings.Trim(fields[i+1], " ,")
			}
		}
	}
	return ""
}
