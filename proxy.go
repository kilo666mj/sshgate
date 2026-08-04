package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/kilo666mj/gatekit/controlplane"
	"github.com/kilo666mj/gatekit/ratelimit"
	"github.com/kilo666mj/gatekit/semaphore"
	"github.com/kilo666mj/gatekit/store"

	"github.com/cloudflare/tableflip"
)

const (
	connRatePerIP      = 1.0
	connBurstPerIP     = 120
	rateLimitTTL       = 5 * time.Minute
	rateSweepPeriod    = time.Minute
	maxConcurrentConns = 1024
	prunePeriod        = time.Minute
	// shutdownGrace bounds how long serve waits for in-flight connections to
	// drain after a SIGINT/SIGTERM before exiting anyway.
	shutdownGrace = 10 * time.Second
	// proxyIdleTimeout tears down an established proxy stream that has made no
	// progress in either direction, so idle/slowloris connections cannot pin
	// the concurrency semaphore and backend sockets indefinitely.
	proxyIdleTimeout = 5 * time.Minute
	// defaultDrainTimeout caps how long a process that has handed off to a new
	// binary (via SIGHUP/tableflip) keeps running to let its existing proxied
	// sessions finish. 0 means wait indefinitely. Modeled on nginx's
	// worker_shutdown_timeout: long enough not to kill live SSH sessions on an
	// upgrade, bounded so departing processes cannot pile up forever.
	defaultDrainTimeout = time.Hour
)

type routeFlag []Route

type Route struct {
	Listen  string
	Backend string
}

func (r *routeFlag) String() string {
	var parts []string
	for _, route := range *r {
		parts = append(parts, route.Listen+"="+route.Backend)
	}
	return strings.Join(parts, ",")
}

func (r *routeFlag) Set(value string) error {
	listen, backend, ok := strings.Cut(value, "=")
	if !ok || listen == "" || backend == "" {
		return fmt.Errorf("route must be LISTEN=BACKEND")
	}
	*r = append(*r, Route{Listen: listen, Backend: backend})
	return nil
}

func cmdServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	dbPath := fs.String("db", defaultDB, "database path")
	configPath := fs.String("config", defaultConfig, "config path")
	allowUnknown := fs.Bool("allow-unknown", false, "allow pending fingerprints")
	drainTimeout := fs.Duration("drain-timeout", defaultDrainTimeout, "on upgrade/shutdown, how long to wait for existing connections to finish (0 = forever)")
	var routes routeFlag
	fs.Var(&routes, "route", "route in LISTEN=BACKEND form, repeatable")
	fs.Parse(args)
	if len(routes) == 0 {
		fatalf("usage: serve --route LISTEN=BACKEND [--route LISTEN=BACKEND]")
	}

	// tableflip coordinates a zero-downtime handoff: on SIGHUP it re-execs the
	// (possibly newly installed) binary, passes it the listening sockets over an
	// inherited control fd, and lets this process keep serving its existing
	// connections until they drain.
	upg, err := tableflip.New(tableflip.Options{})
	if err != nil {
		fatalf("tableflip init: %v", err)
	}
	defer upg.Stop()

	// terminating distinguishes a stop (SIGTERM/SIGINT) from an upgrade handoff
	// once upg.Exit() unblocks, so each can pick the right drain deadline.
	var terminating atomic.Bool
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGINT)
		for s := range sig {
			if s == syscall.SIGHUP {
				log.Printf("SIGHUP: starting upgrade")
				if err := upg.Upgrade(); err != nil {
					log.Printf("upgrade failed: %v", err)
				}
				continue
			}
			// SIGTERM/SIGINT: begin graceful shutdown by unblocking Exit below.
			log.Printf("%s: shutting down", s)
			terminating.Store(true)
			upg.Stop()
			return
		}
	}()

	log.Printf("sshgate version: %s", version)
	log.Printf("database: %s", *dbPath)
	st, err := NewStore(*dbPath)
	if err != nil {
		fatalf("open store: %v", err)
	}
	log.Printf("config: %s", *configPath)
	cfg, err := loadConfig(*configPath)
	if err != nil {
		fatalf("load config: %v", err)
	}
	log.Printf("allow unknown: %t", *allowUnknown)

	// bgCtx stops background writers (pruning, control-plane sync) once this
	// process is draining, so a departing process stops touching the shared
	// database while a newer one owns it.
	bgCtx, stopBackground := context.WithCancel(context.Background())
	defer stopBackground()

	if cfg.MaxFingerprints > 0 {
		log.Printf("max fingerprints: %d", cfg.MaxFingerprints)
		prune := func() {
			if n, err := st.PruneToLimit(cfg.MaxFingerprints); err != nil {
				log.Printf("prune fingerprints: %v", err)
			} else if n > 0 {
				log.Printf("pruned %d fingerprint(s) over limit %d", n, cfg.MaxFingerprints)
			}
		}
		prune()
		go func() {
			t := time.NewTicker(prunePeriod)
			defer t.Stop()
			for {
				select {
				case <-bgCtx.Done():
					return
				case <-t.C:
					prune()
				}
			}
		}()
	}
	if err := controlplane.Start(bgCtx, st, cfg.ControlPlane); err != nil {
		log.Fatalf("control plane: %v", err)
	}

	limiter := ratelimit.New(connRatePerIP, connBurstPerIP, rateLimitTTL)
	go limiter.RunSweeper(rateSweepPeriod, bgCtx.Done())
	sem := semaphore.New(maxConcurrentConns)

	// connWG tracks in-flight connections so the drain phase can wait for them.
	var connWG sync.WaitGroup
	var listeners []net.Listener
	for _, route := range routes {
		route := route
		ln, err := upg.Listen("tcp", route.Listen)
		if err != nil {
			fatalf("listen %s: %v", route.Listen, err)
		}
		listeners = append(listeners, ln)
		log.Printf("LISTEN %s -> %s", route.Listen, route.Backend)
		go serveListener(ln, route, st, *allowUnknown, limiter, sem, &connWG)
	}

	if err := upg.Ready(); err != nil {
		fatalf("tableflip ready: %v", err)
	}
	notifyReady()

	// Block until this process is asked to exit: either a successful upgrade
	// handed serving off to a new process, or a termination signal arrived.
	<-upg.Exit()

	// Stop accepting new connections and stop background DB writers. Existing
	// proxied streams keep running on their own goroutines.
	for _, ln := range listeners {
		_ = ln.Close()
	}
	stopBackground()

	// A terminating shutdown (SIGTERM/SIGINT) drains briefly then exits; an
	// upgrade handoff waits up to --drain-timeout so live SSH sessions survive
	// the binary swap.
	timeout := *drainTimeout
	if terminating.Load() {
		timeout = shutdownGrace
		log.Printf("shutdown: draining in-flight connections (grace %s)", timeout)
	} else {
		log.Printf("upgrade: draining in-flight connections (timeout %s)", timeout)
	}
	drainConnections(&connWG, timeout)
	if err := st.Close(); err != nil {
		log.Printf("shutdown: close store: %v", err)
	}
}

// drainConnections waits for in-flight connections to finish, bounded by
// timeout (0 waits indefinitely). It lets a process that has handed off keep
// serving live SSH sessions instead of dropping them on restart.
func drainConnections(connWG *sync.WaitGroup, timeout time.Duration) {
	done := make(chan struct{})
	go func() {
		connWG.Wait()
		close(done)
	}()
	if timeout <= 0 {
		<-done
		log.Printf("all connections drained")
		return
	}
	select {
	case <-done:
		log.Printf("all connections drained")
	case <-time.After(timeout):
		log.Printf("drain timeout after %s; exiting with connections still open", timeout)
	}
}

func serveListener(ln net.Listener, route Route, st *store.Store, allowUnknown bool, limiter *ratelimit.Limiter, sem *semaphore.Semaphore, connWG *sync.WaitGroup) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			// The listener is closed during drain; stop the accept loop so the
			// process can exit once its existing connections finish.
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("ACCEPT %s: %v", route.Listen, err)
			continue
		}
		clientIP := remoteIP(conn.RemoteAddr())
		if !sem.Acquire() {
			log.Printf("[%s] OVERLOAD dropping connection", clientIP)
			conn.Close()
			continue
		}
		connWG.Add(1)
		go func() {
			defer connWG.Done()
			defer sem.Release()
			handleConn(conn, route, st, allowUnknown, limiter)
		}()
	}
}

func handleConn(client net.Conn, route Route, st *store.Store, allowUnknown bool, limiter *ratelimit.Limiter) {
	defer client.Close()
	clientIP := remoteIP(client.RemoteAddr())
	if !limiter.Allow(clientIP) {
		log.Printf("[%s] RATELIMIT dropping connection", clientIP)
		return
	}

	// SSH clients commonly wait for the server identification before sending
	// KEXINIT, so the proxy has to complete the version-string exchange before
	// it can fingerprint the client. The gate still happens before the client's
	// KEXINIT is forwarded to the backend.
	clientReader := bufio.NewReader(client)
	_ = client.SetReadDeadline(time.Now().Add(10 * time.Second))
	clientID, err := readSSHIdentification(clientReader)
	if err != nil {
		_ = client.SetReadDeadline(time.Time{})
		if isTimeout(err) {
			log.Printf("[%s] TIMEOUT awaiting SSH identification", clientIP)
		} else {
			log.Printf("[%s] BLOCKED malformed SSH identification: %v", clientIP, err)
		}
		return
	}

	backend, err := net.Dial("tcp", route.Backend)
	if err != nil {
		log.Printf("[%s] BACKEND %s: %v", clientIP, route.Backend, err)
		return
	}
	defer backend.Close()

	if _, err := backend.Write(clientID.bytes); err != nil {
		log.Printf("[%s] BACKEND client identification write: %v", clientIP, err)
		return
	}

	backendReader := bufio.NewReader(backend)
	_ = backend.SetReadDeadline(time.Now().Add(10 * time.Second))
	serverID, err := readSSHIdentification(backendReader)
	_ = backend.SetReadDeadline(time.Time{})
	if err != nil {
		if isTimeout(err) {
			log.Printf("[%s] BACKEND TIMEOUT awaiting SSH identification", clientIP)
		} else {
			log.Printf("[%s] BACKEND malformed SSH identification: %v", clientIP, err)
		}
		return
	}
	if _, err := client.Write(serverID.bytes); err != nil {
		log.Printf("[%s] CLIENT server identification write: %v", clientIP, err)
		return
	}

	_ = client.SetReadDeadline(time.Now().Add(10 * time.Second))
	kex, err := readSSHKexInit(clientReader, clientID.id)
	_ = client.SetReadDeadline(time.Time{})
	if err != nil {
		if isTimeout(err) {
			log.Printf("[%s] TIMEOUT awaiting SSH KEXINIT", clientIP)
		} else {
			log.Printf("[%s] BLOCKED malformed SSH KEXINIT: %v", clientIP, err)
		}
		return
	}

	entry, err := st.Observe(store.Observation{
		Fingerprint: kex.fingerprint.Hash,
		IP:          clientIP,
		Meta:        kex.fingerprint.toMeta(),
	}, !allowUnknown)
	if err != nil {
		log.Printf("[%s] BLOCKED store error: %v", clientIP, err)
		return
	}

	switch entry.Status {
	case StatusApproved:
		log.Printf("[%s] APPROVED %s label=%q client=%q", clientIP, kex.fingerprint.Hash, entry.Label, kex.fingerprint.ClientID)
	case StatusBlocked:
		log.Printf("[%s] BLOCKED %s label=%q client=%q", clientIP, kex.fingerprint.Hash, entry.Label, kex.fingerprint.ClientID)
		return
	default:
		if !allowUnknown {
			log.Printf("[%s] PENDING %s client=%q", clientIP, kex.fingerprint.Hash, kex.fingerprint.ClientID)
			return
		}
		log.Printf("[%s] PENDING allowed %s client=%q", clientIP, kex.fingerprint.Hash, kex.fingerprint.ClientID)
	}

	if _, err := backend.Write(kex.bytes); err != nil {
		log.Printf("[%s] BACKEND KEXINIT write: %v", clientIP, err)
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go proxyCopy(&wg, backend, clientReader, client)
	go proxyCopy(&wg, client, backendReader, backend)
	wg.Wait()
}

// closeWriter is implemented by *net.TCPConn; it lets proxyCopy half-close the
// write side so the opposite direction can keep draining.
type closeWriter interface {
	CloseWrite() error
}

// proxyCopy forwards from src (a bufio.Reader wrapping srcConn, so any bytes
// buffered during the handshake are drained first) to dst, refreshing an idle
// timeout on both conns around each read/write.
func proxyCopy(wg *sync.WaitGroup, dst net.Conn, src *bufio.Reader, srcConn net.Conn) {
	defer wg.Done()
	buf := make([]byte, 32*1024)
	for {
		_ = srcConn.SetReadDeadline(time.Now().Add(proxyIdleTimeout))
		n, err := src.Read(buf)
		if n > 0 {
			_ = dst.SetWriteDeadline(time.Now().Add(proxyIdleTimeout))
			if _, werr := dst.Write(buf[:n]); werr != nil {
				// Downstream is broken; fully close to unblock the peer goroutine.
				_ = dst.Close()
				return
			}
		}
		if err != nil {
			// src reached EOF/error: half-close the write side so the opposite
			// direction can keep draining, falling back to a full close if the
			// conn does not support half-close.
			if cw, ok := dst.(closeWriter); ok {
				_ = cw.CloseWrite()
			} else {
				_ = dst.Close()
			}
			return
		}
	}
}

func remoteIP(addr net.Addr) string {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

// isTimeout reports whether err is a network read-deadline timeout, as opposed
// to a parse error from malformed data. Used to distinguish a peer that sent
// nothing in time from one that sent invalid bytes.
func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
