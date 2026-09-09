package main

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMetricsHandlerExposesSSHGateAndRuntimeMetrics(t *testing.T) {
	m := newServerMetrics("test-version")
	m.connectionStarted("[::]:2222")
	m.countBytes("[::]:2222", "client_to_backend", 42)
	m.connectionFinished("[::]:2222", "proxied")

	req := httptest.NewRequest("GET", "/metrics", nil)
	rec := httptest.NewRecorder()
	m.handler().ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		`sshgate_build_info{version="test-version"} 1`,
		`sshgate_connections_total{route="[::]:2222"} 1`,
		`sshgate_active_connections{route="[::]:2222"} 0`,
		`sshgate_connection_results_total{result="proxied",route="[::]:2222"} 1`,
		`sshgate_proxied_bytes_total{direction="client_to_backend",route="[::]:2222"} 42`,
		`go_goroutines`,
		`process_cpu_seconds_total`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics output missing %q", want)
		}
	}
}

func TestMetricsReaderCountsReturnedBytes(t *testing.T) {
	m := newServerMetrics("test")
	r := metricsReader{
		reader:    strings.NewReader("hello"),
		metrics:   m,
		route:     "127.0.0.1:2222",
		direction: "backend_to_client",
	}
	if _, err := io.ReadAll(r); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	m.handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	if want := `sshgate_proxied_bytes_total{direction="backend_to_client",route="127.0.0.1:2222"} 5`; !strings.Contains(rec.Body.String(), want) {
		t.Errorf("metrics output missing %q", want)
	}
}
