package notice

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Sender delivers notices. An error means none of them were delivered.
type Sender interface {
	Send(ctx context.Context, notices []Notice) error
}

// OutboxConfig is what an Outbox needs.
type OutboxConfig struct {
	// Sender delivers the notices. Nil only logs them.
	Sender Sender
	// Logger gets every notice, sent or not.
	Logger     *slog.Logger
	Registerer prometheus.Registerer
	// Max is how many notices may wait to be sent; past it the oldest
	// are dropped. Defaults to 1000.
	Max int
	// Batch is how many are sent at once. Defaults to 100.
	Batch int
	// Retry is how long after a failure the notices waiting are tried
	// again, if no new one comes before. Defaults to a minute.
	Retry time.Duration
}

// Outbox holds the notices until they are sent, and sends again the ones
// that could not be. It holds them in memory: what is waiting when the
// gate stops is lost, though the pairs are still in the daily summary.
type Outbox struct {
	cfg  OutboxConfig
	wake chan struct{}

	mu      sync.Mutex
	pending []queued
	seq     uint64

	put      *prometheus.CounterVec
	failures prometheus.Counter
	dropped  prometheus.Counter
	waiting  prometheus.Gauge
}

// NewOutbox makes an Outbox and registers its metrics.
func NewOutbox(cfg OutboxConfig) *Outbox {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Max <= 0 {
		cfg.Max = 1000
	}
	if cfg.Batch <= 0 {
		cfg.Batch = 100
	}
	if cfg.Retry <= 0 {
		cfg.Retry = time.Minute
	}
	o := &Outbox{
		cfg:  cfg,
		wake: make(chan struct{}, 1),
		put: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "sentinel_notices_total",
			Help: "Notices made, by type, whether or not they could be sent.",
		}, []string{"type"}),
		failures: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "sentinel_notice_send_failures_total",
			Help: "Times the notices waiting could not be sent; they are tried again.",
		}),
		dropped: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "sentinel_notices_dropped_total",
			Help: "Notices dropped unsent because too many were waiting.",
		}),
		waiting: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "sentinel_notices_pending",
			Help: "Notices waiting to be sent.",
		}),
	}
	configured := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "sentinel_notice_sender_configured",
		Help: "1 when the notices are sent to Alertmanager, 0 when they are only logged.",
	})
	if cfg.Sender != nil {
		configured.Set(1)
	}
	if cfg.Registerer != nil {
		cfg.Registerer.MustRegister(o.put, o.failures, o.dropped, o.waiting, configured)
	}
	for _, t := range Types {
		o.put.WithLabelValues(t)
	}
	return o
}

// Put logs n and, with a sender, leaves it to be sent.
func (o *Outbox) Put(n Notice) {
	o.put.WithLabelValues(n.Type).Inc()
	attrs := []any{"type", n.Type, "at", n.At, "summary", n.Summary}
	for k, v := range n.Labels {
		attrs = append(attrs, "label."+k, v)
	}
	o.cfg.Logger.Info("notice", attrs...)
	if o.cfg.Sender == nil {
		return
	}
	o.mu.Lock()
	o.seq++
	o.pending = append(o.pending, queued{seq: o.seq, n: n})
	if over := len(o.pending) - o.cfg.Max; over > 0 {
		o.pending = append([]queued(nil), o.pending[over:]...)
		o.dropped.Add(float64(over))
		o.cfg.Logger.Warn("notices were dropped unsent: too many were waiting", "count", over)
	}
	o.waiting.Set(float64(len(o.pending)))
	o.mu.Unlock()
	select {
	case o.wake <- struct{}{}:
	default:
	}
}

// Pending is how many notices are waiting to be sent.
func (o *Outbox) Pending() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.pending)
}

// Run sends the notices as they are put, and again after Retry those that
// could not be sent, until ctx is done. It then tries once more, briefly,
// to send what is still waiting.
func (o *Outbox) Run(ctx context.Context) {
	if o.cfg.Sender == nil {
		<-ctx.Done()
		return
	}
	retry := time.NewTicker(o.cfg.Retry)
	defer retry.Stop()
	for {
		select {
		case <-ctx.Done():
			last, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			o.flush(last)
			cancel()
			return
		case <-o.wake:
		case <-retry.C:
		}
		o.flush(ctx)
	}
}

// queued is a notice waiting, numbered in the order it was put.
type queued struct {
	seq uint64
	n   Notice
}

// flush sends what is waiting, a batch at a time, until it is all sent or
// a send fails.
func (o *Outbox) flush(ctx context.Context) {
	for {
		o.mu.Lock()
		n := min(len(o.pending), o.cfg.Batch)
		batch := make([]Notice, n)
		var last uint64
		for i, q := range o.pending[:n] {
			batch[i], last = q.n, q.seq
		}
		o.mu.Unlock()
		if n == 0 {
			return
		}
		if err := o.cfg.Sender.Send(ctx, batch); err != nil {
			o.failures.Inc()
			o.cfg.Logger.Error("notices could not be sent; they will be tried again", "count", n, "error", err)
			return
		}
		o.mu.Lock()
		// Put may have dropped some of the batch from the front while it
		// was being sent, so remove by number, not by count.
		i := 0
		for i < len(o.pending) && o.pending[i].seq <= last {
			i++
		}
		o.pending = o.pending[i:]
		o.waiting.Set(float64(len(o.pending)))
		o.mu.Unlock()
	}
}
