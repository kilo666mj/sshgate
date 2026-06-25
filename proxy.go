package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
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
	var routes routeFlag
	fs.Var(&routes, "route", "route in LISTEN=BACKEND form, repeatable")
	fs.Parse(args)
	if len(routes) == 0 {
		fatalf("usage: serve --route LISTEN=BACKEND [--route LISTEN=BACKEND]")
	}

	log.Printf("sshgate version: %s", version)
	log.Printf("database: %s", *dbPath)
	store, err := NewStore(*dbPath)
	if err != nil {
		fatalf("open store: %v", err)
	}
	log.Printf("config: %s", *configPath)
	cfg, err := loadConfig(*configPath)
	if err != nil {
		fatalf("load config: %v", err)
	}
	log.Printf("allow unknown: %t", *allowUnknown)
	if cfg.MaxFingerprints > 0 {
		log.Printf("max fingerprints: %d", cfg.MaxFingerprints)
		prune := func() {
			if n, err := store.PruneToLimit(cfg.MaxFingerprints); err != nil {
				log.Printf("prune fingerprints: %v", err)
			} else if n > 0 {
				log.Printf("pruned %d fingerprint(s) over limit %d", n, cfg.MaxFingerprints)
			}
		}
		prune()
		go func() {
			for range time.Tick(prunePeriod) {
				prune()
			}
		}()
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	limiter := newRateLimiter(connRatePerIP, connBurstPerIP, rateLimitTTL)
	go limiter.runSweeper(rateSweepPeriod)
	sem := newSemaphore(maxConcurrentConns)

	// conns tracks in-flight connection handlers so shutdown can drain them.
	var conns sync.WaitGroup
	var accept sync.WaitGroup
	var listeners []net.Listener
	for _, route := range routes {
		route := route
		ln, err := net.Listen("tcp", route.Listen)
		if err != nil {
			fatalf("listen %s: %v", route.Listen, err)
		}
		log.Printf("LISTEN %s -> %s", route.Listen, route.Backend)
		listeners = append(listeners, ln)
		accept.Add(1)
		go func() {
			defer accept.Done()
			serveListener(ctx, ln, route, store, *allowUnknown, limiter, sem, &conns)
		}()
	}

	// On signal, close listeners so the Accept loops return.
	go func() {
		<-ctx.Done()
		log.Printf("shutdown: closing listeners, draining in-flight connections")
		for _, ln := range listeners {
			ln.Close()
		}
	}()

	accept.Wait()

	// Wait for in-flight connections to finish, bounded by shutdownGrace.
	drained := make(chan struct{})
	go func() {
		conns.Wait()
		close(drained)
	}()
	select {
	case <-drained:
	case <-time.After(shutdownGrace):
		log.Printf("shutdown: grace period elapsed with connections still active")
	}
	if err := store.Close(); err != nil {
		log.Printf("shutdown: close store: %v", err)
	}
}

func serveListener(ctx context.Context, ln net.Listener, route Route, store *Store, allowUnknown bool, limiter *rateLimiter, sem *semaphore, conns *sync.WaitGroup) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				// Listener was closed for shutdown; stop accepting.
				return
			}
			log.Printf("ACCEPT %s: %v", route.Listen, err)
			continue
		}
		clientIP := remoteIP(conn.RemoteAddr())
		if !sem.acquire() {
			log.Printf("[%s] OVERLOAD dropping connection", clientIP)
			conn.Close()
			continue
		}
		conns.Add(1)
		go func() {
			defer conns.Done()
			defer sem.release()
			handleConn(conn, route, store, allowUnknown, limiter)
		}()
	}
}

func handleConn(client net.Conn, route Route, store *Store, allowUnknown bool, limiter *rateLimiter) {
	defer client.Close()
	clientIP := remoteIP(client.RemoteAddr())
	if !limiter.allow(clientIP) {
		log.Printf("[%s] RATELIMIT dropping connection", clientIP)
		return
	}

	// Read the client identification and KEXINIT up front, before touching the
	// backend. RFC 4253 lets a client send KEXINIT immediately after its banner
	// without waiting for the server's, and OpenSSH does; reading both here means
	// a blocked or pending fingerprint never opens a backend connection or learns
	// the server's banner. A client that withholds KEXINIT until it sees the
	// server's identification will time out here instead -- acceptable for this
	// proxy's threat model.
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

	entry, err := store.Observe(kex.fingerprint, clientIP, !allowUnknown)
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

	// Verdict allows the connection: dial the backend and replay the client
	// identification + KEXINIT we already consumed.
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
