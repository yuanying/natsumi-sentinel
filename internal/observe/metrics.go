package observe

import (
	"context"
	"errors"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/yuanying/natsumi-sentinel/internal/audit"
	"github.com/yuanying/natsumi-sentinel/internal/authdclient"
	"github.com/yuanying/natsumi-sentinel/internal/routes"
)

// NotListed is the destination label of a name the routing table does not
// list: the workspace can make up any number of those.
const NotListed = "(not-listed)"

// GateMetrics are the gate's metrics of what goes through it.
type GateMetrics struct {
	routes func() *routes.Table
	fixed  map[string]bool

	requests         *prometheus.CounterVec
	writeFailures    *prometheus.CounterVec
	reloadFailures   prometheus.Counter
	upstreamFailures *prometheus.CounterVec
}

// NewGateMetrics registers the gate's metrics on reg. table is the table
// in use, which says which names may be labels; fixed are the gate's own
// names, which may be too.
func NewGateMetrics(reg prometheus.Registerer, table func() *routes.Table, fixed []string) *GateMetrics {
	m := &GateMetrics{
		routes: table,
		fixed:  map[string]bool{},
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "sentinel_requests_total",
			Help: "What went through the gate or was refused by it, as recorded: requests, connections, passthroughs, name resolution and the gate's own requests.",
		}, []string{"source", "kind", "treatment", "destination", "verdict"}),
		writeFailures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "sentinel_audit_write_failures_total",
			Help: "Audit records that could not be written, by the step that failed. What could not be recorded at begin or write was not let through.",
		}, []string{"stage"}),
		reloadFailures: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "sentinel_routes_reload_failures_total",
			Help: "Times the routing table changed into one that could not be read, or its directory could not be read; the table read before stays in use.",
		}),
		upstreamFailures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "sentinel_upstream_failures_total",
			Help: "Requests the gate allowed but could not get an upstream's answer for, by authd's reason, or authd-unreachable when authd itself could not be reached.",
		}, []string{"destination", "reason"}),
	}
	for _, name := range fixed {
		m.fixed[routes.Normalize(name)] = true
	}
	reg.MustRegister(m.requests, m.writeFailures, m.reloadFailures, m.upstreamFailures)
	for _, s := range []Stage{Write, Begin, Finish} {
		m.writeFailures.WithLabelValues(string(s))
	}
	return m
}

// Observe counts one event. It is meant to be given to NewRecorder.
func (m *GateMetrics) Observe(ev Event) {
	rec := &ev.Record
	if ev.Err != nil {
		m.writeFailures.WithLabelValues(string(ev.Stage)).Inc()
	}
	if rec.Kind == audit.KindConfig {
		if rec.Verdict == audit.Deny {
			m.reloadFailures.Inc()
		}
		return
	}
	switch {
	case ev.Stage == Begin:
		// Counted when it is finished.
		return
	case ev.Stage == Write && ev.Err != nil:
		// It was not let through, whatever the record says.
		return
	}
	m.requests.WithLabelValues(rec.Source, string(rec.Kind), rec.Treatment, m.destination(rec), string(rec.Verdict)).Inc()
}

// destination is the label for a record's destination: a name the owner
// chose (in the routing table, or the gate's own), or NotListed.
func (m *GateMetrics) destination(rec *audit.Record) string {
	switch {
	case rec.Kind == audit.KindPassthrough || rec.Name == "":
		// A passthrough has an address, not a name, and the address
		// can be anything in its range.
		return ""
	case rec.Kind == audit.KindGate:
		// The gate's own requests go where its flags say.
		return rec.Name
	case m.fixed[routes.Normalize(rec.Name)] || m.routes().Listed(rec.Name):
		return routes.Normalize(rec.Name)
	default:
		return NotListed
	}
}

// Upstream wraps the gate's sender to authd, counting the requests it
// could not get an answer for.
func (m *GateMetrics) Upstream(rt http.RoundTripper) http.RoundTripper {
	return &countingTripper{inner: rt, m: m}
}

type countingTripper struct {
	inner http.RoundTripper
	m     *GateMetrics
}

func (c *countingTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := c.inner.RoundTrip(req)
	if err == nil || errors.Is(err, context.Canceled) {
		return resp, err
	}
	dest := routes.Normalize(req.URL.Hostname())
	if !c.m.routes().Listed(dest) {
		dest = NotListed
	}
	c.m.upstreamFailures.WithLabelValues(dest, failureReason(err)).Inc()
	return resp, err
}

// failureReason is the label for a failure: authd's reason when it is one
// this build knows, so that a newer authd cannot widen the label.
func failureReason(err error) string {
	var aerr *authdclient.Error
	if !errors.As(err, &aerr) {
		return "authd-unreachable"
	}
	switch aerr.Reason {
	case authdclient.ReasonUpstreamNotRegistered, authdclient.ReasonSurrogateMismatch,
		authdclient.ReasonCredentialUnavailable, authdclient.ReasonBadRequest,
		authdclient.ReasonUpstreamUnreachable, authdclient.ReasonUpstreamCertificate,
		authdclient.ReasonUpstreamFailed:
		return string(aerr.Reason)
	default:
		return "other"
	}
}
