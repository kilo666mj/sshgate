package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"unicode"
)

const (
	defaultDB = "/var/lib/sshgate/sshgate.db"

	StatusPending  = "pending"
	StatusApproved = "approved"
	StatusBlocked  = "blocked"
)

// version is the build version, overridden via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	log.SetFlags(log.LstdFlags)
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "serve":
		cmdServe(os.Args[2:])
	case "list":
		cmdList(os.Args[2:])
	case "approve":
		cmdSetStatus(os.Args[2:], StatusApproved)
	case "block":
		cmdSetStatus(os.Args[2:], StatusBlocked)
	case "pending":
		cmdSetStatus(os.Args[2:], StatusPending)
	case "label":
		cmdLabel(os.Args[2:])
	case "delete":
		cmdDelete(os.Args[2:])
	case "correlate":
		cmdCorrelate(os.Args[2:])
	case "version", "-version", "--version":
		fmt.Println(version)
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `usage: sshgate <command> [options]

commands:
  serve       run the SSH fingerprinting proxy
  list        list known fingerprints
  approve     approve a fingerprint
  block       block a fingerprint
  pending     mark a fingerprint pending
  label       label a fingerprint
  delete      delete a fingerprint
  correlate   correlate a fingerprint with sshd logs
  version     print the build version
`)
}

func fatalf(format string, args ...any) {
	log.Fatalf(format, args...)
}

func cmdList(args []string) {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	dbPath := fs.String("db", defaultDB, "database path")
	verbose := fs.Bool("v", false, "include SSH metadata")
	fs.Parse(args)

	store, err := NewStore(*dbPath)
	if err != nil {
		fatalf("open store: %v", err)
	}
	entries, err := store.List()
	if err != nil {
		fatalf("list fingerprints: %v", err)
	}

	var fps []string
	for fp := range entries {
		fps = append(fps, fp)
	}
	sort.Strings(fps)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	if *verbose {
		fmt.Fprintln(w, "FINGERPRINT\tSTATUS\tLABEL\tFIRST_SEEN\tLAST_SEEN\tIPS\tCLIENT\tRAW")
	} else {
		fmt.Fprintln(w, "FINGERPRINT\tSTATUS\tLABEL\tFIRST_SEEN\tLAST_SEEN\tIPS")
	}
	for _, fp := range fps {
		e := entries[fp]
		if *verbose {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
				fp, e.Status, valueOrDash(e.Label), formatTime(e.FirstSeen),
				formatTime(e.LastSeen), joinOrDash(e.IPs),
				valueOrDash(sanitizeDisplay(e.ClientID)),
				valueOrDash(sanitizeDisplay(e.Raw)),
			)
			continue
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			fp, e.Status, valueOrDash(e.Label), formatTime(e.FirstSeen),
			formatTime(e.LastSeen), joinOrDash(e.IPs),
		)
	}
	w.Flush()
}

func cmdSetStatus(args []string, status string) {
	fs := flag.NewFlagSet(status, flag.ExitOnError)
	dbPath := fs.String("db", defaultDB, "database path")
	label := fs.String("label", "", "label to assign")
	register := fs.Bool("register", false, "create the fingerprint if it has not been observed yet (requires a full fingerprint hash)")
	fs.Parse(args)
	if fs.NArg() != 1 {
		fatalf("usage: %s [--label <label>] [--register] <fingerprint>", status)
	}

	store, err := NewStore(*dbPath)
	if err != nil {
		fatalf("open store: %v", err)
	}

	if *register {
		fp := strings.ToLower(fs.Arg(0))
		if !isFingerprintHash(fp) {
			fatalf("--register requires a full %d-character hex fingerprint", fingerprintHashLen)
		}
		if err := store.UpsertStatus(fp, status, *label); err != nil {
			fatalf("set status: %v", err)
		}
		return
	}

	fp, err := store.ResolveFingerprint(fs.Arg(0))
	if err != nil {
		fatalf("%v", err)
	}
	if err := store.SetStatus(fp, status, *label); err != nil {
		fatalf("set status: %v", err)
	}
}

const fingerprintHashLen = 32

// isFingerprintHash reports whether s is a full fingerprint hash as produced by
// parseKexInit: a lowercase 32-character hex string.
func isFingerprintHash(s string) bool {
	if len(s) != fingerprintHashLen {
		return false
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
		default:
			return false
		}
	}
	return true
}

func cmdLabel(args []string) {
	fs := flag.NewFlagSet("label", flag.ExitOnError)
	dbPath := fs.String("db", defaultDB, "database path")
	fs.Parse(args)
	if fs.NArg() != 2 {
		fatalf("usage: label <fingerprint> <label>")
	}

	store, err := NewStore(*dbPath)
	if err != nil {
		fatalf("open store: %v", err)
	}
	fp, err := store.ResolveFingerprint(fs.Arg(0))
	if err != nil {
		fatalf("%v", err)
	}
	if err := store.Label(fp, fs.Arg(1)); err != nil {
		fatalf("label: %v", err)
	}
}

func cmdDelete(args []string) {
	fs := flag.NewFlagSet("delete", flag.ExitOnError)
	dbPath := fs.String("db", defaultDB, "database path")
	fs.Parse(args)
	if fs.NArg() != 1 {
		fatalf("usage: delete <fingerprint>")
	}

	store, err := NewStore(*dbPath)
	if err != nil {
		fatalf("open store: %v", err)
	}
	fp, err := store.ResolveFingerprint(fs.Arg(0))
	if err != nil {
		fatalf("%v", err)
	}
	if err := store.Delete(fp); err != nil {
		fatalf("delete: %v", err)
	}
}

func valueOrDash(v string) string {
	if v == "" {
		return "-"
	}
	return v
}

// sanitizeDisplay neutralizes control characters in attacker-controlled strings
// (SSH client IDs, raw KEXINIT material, log lines) before they are printed to
// an operator's terminal, preventing ANSI/control-sequence injection.
func sanitizeDisplay(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case '\t', '\n', '\r':
			return ' '
		}
		if unicode.IsControl(r) {
			return '�'
		}
		return r
	}, s)
}

func joinOrDash(values []string) string {
	if len(values) == 0 {
		return "-"
	}
	out := values[0]
	for _, v := range values[1:] {
		out += "," + v
	}
	return out
}

func formatTime(t Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Format("2006-01-02 15:04:05")
}

var errBlocked = errors.New("blocked")
