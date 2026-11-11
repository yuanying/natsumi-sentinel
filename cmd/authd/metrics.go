package main

import (
	"strconv"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/yuanying/natsumi-sentinel/internal/authdclient"
	"github.com/yuanying/natsumi-sentinel/internal/metrics"
)

// authdMetrics are authd's own metrics (docs/metrics.md). Their labels take
// only authd's reasons and positions in the registration: never a key, a
// surrogate or anything the workspace chose.
type authdMetrics struct {
	reg          *prometheus.Registry
	refusals     *prometheus.CounterVec
	failures     *prometheus.CounterVec
	keyFailures  *prometheus.CounterVec
	refusedPeers prometheus.Counter
}

func newAuthdMetrics(credentials int) *authdMetrics {
	m := &authdMetrics{
		reg: metrics.NewRegistry(program, version),
		refusals: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "authd_refusals_total",
			Help: "Requests authd refused by its own checks, sending nothing upstream, by reason.",
		}, []string{"reason"}),
		failures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "authd_upstream_failures_total",
			Help: "Requests that passed authd's checks but got no answer from the upstream, by reason.",
		}, []string{"reason"}),
		keyFailures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "authd_key_read_failures_total",
			Help: "Times a real key's file could not be read when it was to be used, by the credential's position in the registration (0 for the first).",
		}, []string{"credential"}),
		refusedPeers: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "authd_refused_peers_total",
			Help: "Connections to authd's socket closed unread because they came from a UID other than the gate's.",
		}),
	}
	m.reg.MustRegister(m.refusals, m.failures, m.keyFailures, m.refusedPeers)
	// Every series is there from the start at 0, so that a rule on its
	// increase sees the first one.
	for _, r := range []authdclient.Reason{
		authdclient.ReasonUpstreamNotRegistered, authdclient.ReasonSurrogateMismatch,
		authdclient.ReasonCredentialUnavailable, authdclient.ReasonBadRequest,
	} {
		m.refusals.WithLabelValues(string(r))
	}
	for _, r := range []authdclient.Reason{
		authdclient.ReasonUpstreamUnreachable, authdclient.ReasonUpstreamCertificate, authdclient.ReasonUpstreamFailed,
	} {
		m.failures.WithLabelValues(string(r))
	}
	for i := range credentials {
		m.keyFailures.WithLabelValues(strconv.Itoa(i))
	}
	return m
}

func (m *authdMetrics) onError(r authdclient.Reason) {
	e := authdclient.Error{Reason: r}
	if e.Refused() {
		m.refusals.WithLabelValues(string(r)).Inc()
		return
	}
	m.failures.WithLabelValues(string(r)).Inc()
}

func (m *authdMetrics) onKeyUnreadable(credential int) {
	m.keyFailures.WithLabelValues(strconv.Itoa(credential)).Inc()
}
