package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	gateproxy "github.com/kilo666mj/gatekit/proxy"
)

func cmdDoctor(args []string) {
	if err := runDoctor(args, os.Stdout); err != nil {
		fatalf("doctor: %v", err)
	}
}

// runDoctor validates startup inputs without listening, connecting to the
// backend, or opening the SQLite store. Keeping it read-only makes it safe to
// run while sshgate is serving traffic.
func runDoctor(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dbPath := fs.String("db", defaultDB, "database path")
	configPath := fs.String("config", defaultConfig, "config path")
	allowUnknown := fs.Bool("allow-unknown", false, "report enrollment mode")
	var routes gateproxy.Routes
	fs.Var(&routes, "route", "route in LISTEN=BACKEND form, repeatable")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}

	fmt.Fprintf(out, "version: %s\n", version)
	fmt.Fprintf(out, "database: %s", *dbPath)
	if info, err := os.Stat(*dbPath); err == nil {
		fmt.Fprintf(out, " (present, mode %s)\n", info.Mode().Perm())
	} else if os.IsNotExist(err) {
		fmt.Fprintln(out, " (not created yet)")
	} else {
		return fmt.Errorf("inspect database: %w", err)
	}

	fmt.Fprintf(out, "config: %s", *configPath)
	if _, err := os.Stat(*configPath); err == nil {
		fmt.Fprintln(out, " (present)")
	} else if os.IsNotExist(err) {
		fmt.Fprintln(out, " (absent; built-in defaults apply)")
	} else {
		return fmt.Errorf("inspect config: %w", err)
	}
	cfg, err := loadConfig(*configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	fmt.Fprintf(out, "max fingerprints: %d\n", cfg.MaxFingerprints)
	if cfg.ControlPlane.Enabled() {
		if err := cfg.ControlPlane.Validate(); err != nil {
			return err
		}
		fmt.Fprintf(out, "control plane: enabled (%s)\n", cfg.ControlPlane.URL)
	} else {
		fmt.Fprintln(out, "control plane: disabled")
	}

	if *allowUnknown {
		fmt.Fprintln(out, "unknown fingerprints: allowed as pending (enrollment mode)")
	} else {
		fmt.Fprintln(out, "unknown fingerprints: blocked")
	}
	if len(routes) == 0 {
		fmt.Fprintln(out, "routes: none supplied; pass the same --route flags used by serve")
	} else {
		for _, route := range routes {
			fmt.Fprintf(out, "route: %s -> %s\n", route.Listen, route.Backend)
		}
	}
	return nil
}
