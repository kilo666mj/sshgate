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

	if err := writeOutput(out, "version: %s\n", version); err != nil {
		return err
	}
	if err := writeOutput(out, "database: %s", *dbPath); err != nil {
		return err
	}
	if info, err := os.Stat(*dbPath); err == nil {
		if err := writeOutput(out, " (present, mode %s)\n", info.Mode().Perm()); err != nil {
			return err
		}
	} else if os.IsNotExist(err) {
		if err := writeOutput(out, " (not created yet)\n"); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("inspect database: %w", err)
	}

	if err := writeOutput(out, "config: %s", *configPath); err != nil {
		return err
	}
	if _, err := os.Stat(*configPath); err == nil {
		if err := writeOutput(out, " (present)\n"); err != nil {
			return err
		}
	} else if os.IsNotExist(err) {
		if err := writeOutput(out, " (absent; built-in defaults apply)\n"); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("inspect config: %w", err)
	}
	cfg, err := loadConfig(*configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if err := writeOutput(out, "max fingerprints: %d\n", cfg.MaxFingerprints); err != nil {
		return err
	}
	if cfg.ControlPlane.Enabled() {
		if err := cfg.ControlPlane.Validate(); err != nil {
			return err
		}
		if err := writeOutput(out, "control plane: enabled (%s)\n", cfg.ControlPlane.URL); err != nil {
			return err
		}
	} else {
		if err := writeOutput(out, "control plane: disabled\n"); err != nil {
			return err
		}
	}

	if *allowUnknown {
		if err := writeOutput(out, "unknown fingerprints: allowed as pending (enrollment mode)\n"); err != nil {
			return err
		}
	} else {
		if err := writeOutput(out, "unknown fingerprints: blocked\n"); err != nil {
			return err
		}
	}
	if len(routes) == 0 {
		if err := writeOutput(out, "routes: none supplied; pass the same --route flags used by serve\n"); err != nil {
			return err
		}
	} else {
		for _, route := range routes {
			if err := writeOutput(out, "route: %s -> %s\n", route.Listen, route.Backend); err != nil {
				return err
			}
		}
	}
	return nil
}

func writeOutput(w io.Writer, format string, args ...any) error {
	if _, err := fmt.Fprintf(w, format, args...); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	return nil
}
