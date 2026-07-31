package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Collector exposes a Prometheus registry, custom domain counters/histograms, and handler.
type Collector struct {
	registry *prometheus.Registry
	handler  http.Handler

	AuthAttempts  *prometheus.CounterVec
	AuthSuccesses *prometheus.CounterVec
	AuthFailures  *prometheus.CounterVec
	ActiveSessions prometheus.Gauge
	HTTPRequestDuration *prometheus.HistogramVec
}

// NewPrometheusCollector creates a dedicated Prometheus registry and metric instruments.
func NewPrometheusCollector() (*Collector, error) {
	registry := prometheus.NewRegistry()
	registry.MustRegister(prometheus.NewGoCollector())
	registry.MustRegister(prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))

	authAttempts := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "auth_attempts_total",
		Help: "Total number of authentication attempts",
	}, []string{"action"})

	authSuccesses := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "auth_successes_total",
		Help: "Total number of successful authentication attempts",
	}, []string{"action"})

	authFailures := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "auth_failures_total",
		Help: "Total number of failed authentication attempts",
	}, []string{"action", "reason"})

	activeSessions := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "auth_active_sessions",
		Help: "Current number of active sessions in memory/cache",
	})

	httpReqDuration := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "http_request_duration_seconds",
		Help:    "Histogram of HTTP request durations",
		Buckets: prometheus.DefBuckets,
	}, []string{"method", "route", "status"})

	registry.MustRegister(authAttempts, authSuccesses, authFailures, activeSessions, httpReqDuration)

	c := &Collector{
		registry:            registry,
		AuthAttempts:        authAttempts,
		AuthSuccesses:       authSuccesses,
		AuthFailures:        authFailures,
		ActiveSessions:      activeSessions,
		HTTPRequestDuration: httpReqDuration,
	}

	c.handler = promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
	return c, nil
}

// Handler returns the HTTP handler that serves metrics.
func (c *Collector) Handler() http.Handler {
	return c.handler
}
