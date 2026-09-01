package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"
)

const defaultAuthLog = "/var/log/auth.log"

type logMatch struct {
	when time.Time
	ip   string
	user string
	line string
}

func cmdCorrelate(args []string) {
	fs := flag.NewFlagSet("correlate", flag.ExitOnError)
	dbPath := fs.String("db", defaultDB, "database path")
	logPath := fs.String("log", defaultAuthLog, "sshd log path")
	window := fs.Duration("window", 2*time.Minute, "time window around first/last seen")
	limit := fs.Int("limit", 100, "maximum matches to print")
	if err := fs.Parse(args); err != nil {
		fatalf("parse correlate options: %v", err)
	}
	if fs.NArg() != 1 {
		fatalf("usage: correlate [--log <path>] [--window <duration>] <fingerprint>")
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

	matches, err := correlateSSHDLog(*logPath, entry, *window, *limit)
	if err != nil {
		fatalf("correlate sshd log: %v", err)
	}

	fmt.Printf("fingerprint: %s\n", fp)
	if entry.Label != "" {
		fmt.Printf("label: %s\n", entry.Label)
	}
	fmt.Printf("window: +/- %s around first_seen=%s and last_seen=%s\n",
		window.String(), formatTime(entry.FirstSeen), formatTime(entry.LastSeen))
	if len(matches) == 0 {
		fmt.Println("no matching sshd log lines found")
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	writeOrFatal(w, "TIME\tIP\tUSER\tLINE\n")
	for _, m := range matches {
		writeOrFatal(w, "%s\t%s\t%s\t%s\n",
			m.when.Format("2006-01-02 15:04:05"),
			m.ip,
			valueOrDash(sanitizeDisplay(m.user)),
			sanitizeDisplay(m.line),
		)
	}
	flushOrFatal(w)
}

func correlateSSHDLog(path string, entry Entry, window time.Duration, limit int) (_ []logMatch, err error) {
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
		ip, ok := lineContainsAnyIP(line, ips)
		if !ok {
			continue
		}
		when, ok := parseLogTime(line, entry.LastSeen.Time)
		if !ok || !withinCorrelationWindows(when, entry, window) {
			continue
		}
		matches = append(matches, logMatch{
			when: when,
			ip:   ip,
			user: extractSSHUser(line),
			line: line,
		})
		if limit > 0 && len(matches) >= limit {
			break
		}
	}
	return matches, scanner.Err()
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
