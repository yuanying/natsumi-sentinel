package observe

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/yuanying/natsumi-sentinel/internal/ledger"
	"github.com/yuanying/natsumi-sentinel/internal/upstream"
)

// DirectSender is the gate's own sending, as gate.DirectSender is.
type DirectSender interface {
	http.RoundTripper
	Dial(ctx context.Context, name string, port uint16) (*upstream.Conn, error)
}

// Direct wraps the gate's own sending, counting what it refused to send or
// could not get an answer for in sentinel_upstream_failures_total, by the
// reasons of internal/upstream. What it sends for is a destination grant's,
// never a name of the table: the destination label is NotListed.
func (m *GateMetrics) Direct(s DirectSender) DirectSender {
	return &countingDirect{inner: s, m: m}
}

type countingDirect struct {
	inner DirectSender
	m     *GateMetrics
}

func (c *countingDirect) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := c.inner.RoundTrip(req)
	c.count(err)
	return resp, err
}

func (c *countingDirect) Dial(ctx context.Context, name string, port uint16) (*upstream.Conn, error) {
	conn, err := c.inner.Dial(ctx, name, port)
	c.count(err)
	return conn, err
}

func (c *countingDirect) count(err error) {
	if err == nil || errors.Is(err, context.Canceled) {
		return
	}
	c.m.upstreamFailures.WithLabelValues(NotListed, failureReason(err)).Inc()
}

// DestinationMetrics are the metrics of the destination grants
// (docs/metrics.md).
type DestinationMetrics struct {
	dropped, unkept prometheus.Counter
}

// NewDestinationMetrics registers the metrics of the destination grants
// on reg: the grants in effect and the refused names remembered, read from
// the ledger at each scrape (and left out of a scrape when it cannot be
// read), and the refused names dropped or not kept, counted as they are
// told to Remembered.
func NewDestinationMetrics(reg prometheus.Registerer, grants func(context.Context) (map[ledger.GrantShape]int, error), refused func(context.Context) (int, error), logger *slog.Logger) *DestinationMetrics {
	if logger == nil {
		logger = slog.Default()
	}
	m := &DestinationMetrics{
		dropped: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "sentinel_refused_names_dropped_total",
			Help: "Refused names dropped from the ledger's list to keep it to its limit.",
		}),
		unkept: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "sentinel_refused_names_unkept_total",
			Help: "Refused names that could not be kept on the ledger's list; they were refused all the same.",
		}),
	}
	reg.MustRegister(m.dropped, m.unkept, &destinationCounts{
		grantsDesc:  prometheus.NewDesc("sentinel_destination_grants", "Destination grants in effect, by handling and access, read from the ledger; left out when it cannot be read.", []string{"handling", "access"}, nil),
		refusedDesc: prometheus.NewDesc("sentinel_refused_names", "Refused names on the ledger's list, read from the ledger; left out when it cannot be read.", nil, nil),
		grants:      grants, refused: refused, logger: logger,
	})
	return m
}

// Remembered counts what remembering one refused name came to. It is
// meant to be given to dnsgate.Config.Remembered.
func (m *DestinationMetrics) Remembered(dropped int, err error) {
	m.dropped.Add(float64(dropped))
	if err != nil {
		m.unkept.Inc()
	}
}

type destinationCounts struct {
	grantsDesc, refusedDesc *prometheus.Desc
	grants                  func(context.Context) (map[ledger.GrantShape]int, error)
	refused                 func(context.Context) (int, error)
	logger                  *slog.Logger
}

func (d *destinationCounts) Describe(ch chan<- *prometheus.Desc) {
	ch <- d.grantsDesc
	ch <- d.refusedDesc
}

func (d *destinationCounts) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if gs, err := d.grants(ctx); err != nil {
		d.logger.Error("the destination grants could not be counted from the ledger", "error", err)
	} else {
		for s, n := range gs {
			ch <- prometheus.MustNewConstMetric(d.grantsDesc, prometheus.GaugeValue, float64(n), string(s.Handling), string(s.Access))
		}
	}
	if n, err := d.refused(ctx); err != nil {
		d.logger.Error("the refused names could not be counted from the ledger", "error", err)
	} else {
		ch <- prometheus.MustNewConstMetric(d.refusedDesc, prometheus.GaugeValue, float64(n))
	}
}
