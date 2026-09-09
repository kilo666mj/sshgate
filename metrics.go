package main

import (
	"io"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type serverMetrics struct {
	connections *prometheus.CounterVec
	active      *prometheus.GaugeVec
	results     *prometheus.CounterVec
	bytes       *prometheus.CounterVec
	registry    *prometheus.Registry
}

func newServerMetrics(buildVersion string) *serverMetrics {
	registry := prometheus.NewRegistry()
	m := &serverMetrics{
		connections: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "sshgate",
			Name:      "connections_total",
			Help:      "SSH connections accepted for fingerprint processing.",
		}, []string{"route"}),
		active: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "sshgate",
			Name:      "active_connections",
			Help:      "SSH connections currently being processed or proxied.",
		}, []string{"route"}),
		results: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "sshgate",
			Name:      "connection_results_total",
			Help:      "Completed SSH connections by terminal result.",
		}, []string{"route", "result"}),
		bytes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "sshgate",
			Name:      "proxied_bytes_total",
			Help:      "Bytes forwarded for approved or enrollment-mode SSH connections.",
		}, []string{"route", "direction"}),
		registry: registry,
	}
	registry.MustRegister(
		m.connections,
		m.active,
		m.results,
		m.bytes,
		prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}),
		prometheus.NewGoCollector(),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Namespace:   "sshgate",
			Name:        "build_info",
			Help:        "Build information for the running sshgate binary.",
			ConstLabels: prometheus.Labels{"version": buildVersion},
		}, func() float64 { return 1 }),
	)
	return m
}

func (m *serverMetrics) handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

func (m *serverMetrics) initializeRoute(route string) {
	if m == nil {
		return
	}
	m.connections.WithLabelValues(route).Add(0)
	m.active.WithLabelValues(route).Set(0)
	m.bytes.WithLabelValues(route, "client_to_backend").Add(0)
	m.bytes.WithLabelValues(route, "backend_to_client").Add(0)
}

func (m *serverMetrics) connectionStarted(route string) {
	if m == nil {
		return
	}
	m.connections.WithLabelValues(route).Inc()
	m.active.WithLabelValues(route).Inc()
}

func (m *serverMetrics) connectionFinished(route, result string) {
	if m == nil {
		return
	}
	m.active.WithLabelValues(route).Dec()
	m.results.WithLabelValues(route, result).Inc()
}

func (m *serverMetrics) countBytes(route, direction string, n int) {
	if m != nil && n > 0 {
		m.bytes.WithLabelValues(route, direction).Add(float64(n))
	}
}

type metricsReader struct {
	reader    io.Reader
	metrics   *serverMetrics
	route     string
	direction string
}

func (r metricsReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	r.metrics.countBytes(r.route, r.direction, n)
	return n, err
}
