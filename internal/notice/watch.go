package notice

import (
	"context"
	"fmt"
	"log/slog"
	"time"
	"unicode/utf8"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/yuanying/natsumi-sentinel/internal/audit"
	"github.com/yuanying/natsumi-sentinel/internal/observe"
)

// SeenLog keeps the pairs seen.
type SeenLog interface {
	MarkSeen(ctx context.Context, s audit.Seen) (bool, error)
}

// WatcherConfig is what a Watcher needs.
type WatcherConfig struct {
	Log        SeenLog
	Outbox     *Outbox
	Logger     *slog.Logger
	Registerer prometheus.Registerer
	// Buffer is how many records may wait to be looked at. Defaults to
	// 4096.
	Buffer int
}

// Watcher looks at each record as it is written, and puts a notice for
// each pair in it that was not seen before.
type Watcher struct {
	cfg       WatcherConfig
	events    chan audit.Record
	unchecked prometheus.Counter
}

// NewWatcher makes a Watcher and registers its metric.
func NewWatcher(cfg WatcherConfig) *Watcher {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Buffer <= 0 {
		cfg.Buffer = 4096
	}
	w := &Watcher{
		cfg:    cfg,
		events: make(chan audit.Record, cfg.Buffer),
		unchecked: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "sentinel_notice_records_unchecked_total",
			Help: "Records not looked at for pairs seen for the first time: too many were waiting, or the pairs could not be kept.",
		}),
	}
	if cfg.Registerer != nil {
		cfg.Registerer.MustRegister(w.unchecked)
	}
	return w
}

// Observe takes one event from the audit log. It never blocks: what it has
// no room for is counted and left. It is meant to be given to
// observe.NewRecorder.
func (w *Watcher) Observe(ev observe.Event) {
	if ev.Err != nil || ev.Stage == observe.Begin || len(Pairs(&ev.Record)) == 0 {
		return
	}
	select {
	case w.events <- ev.Record:
	default:
		w.unchecked.Inc()
	}
}

// Run looks at the records until ctx is done.
func (w *Watcher) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case rec := <-w.events:
			w.look(ctx, &rec)
		}
	}
}

func (w *Watcher) look(ctx context.Context, rec *audit.Record) {
	for _, s := range Pairs(rec) {
		isNew, err := w.cfg.Log.MarkSeen(ctx, s)
		if err != nil {
			w.unchecked.Inc()
			w.cfg.Logger.Error("a pair seen could not be kept, so whether it is new is not known", "pair", s.Pair, "record", s.Record, "error", err)
			continue
		}
		if isNew {
			w.cfg.Outbox.Put(firstSeenNotice(rec, s))
		}
	}
}

// The longest label value and description, in bytes. A path is the
// workspace's to choose and can be long.
const (
	maxLabel       = 256
	maxDescription = 2048
)

var pairWords = map[string]string{
	PairDestination: "a destination",
	PairWrite:       "a write",
	PairOperation:   "an operation",
	PairPassthrough: "a passthrough",
	PairDeniedName:  "a name refused in name resolution",
}

func firstSeenNotice(rec *audit.Record, s audit.Seen) Notice {
	what := pairWords[s.Pair]
	return Notice{
		Type: TypeFirstSeen,
		At:   s.First,
		Labels: map[string]string{
			"pair":   s.Pair,
			"key":    clip(s.Key, maxLabel),
			"source": rec.Source,
		},
		Summary: clip(fmt.Sprintf("First seen, %s: %s", what, s.Key), maxLabel),
		Description: clip(fmt.Sprintf("The gate saw %s for the first time: %s. From %s, audit record %d, %s.",
			what, s.Key, rec.Source, s.Record, s.First.UTC().Format(time.RFC3339)), maxDescription),
	}
}

// clip cuts s to at most n bytes, at a rune boundary, marking the cut.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	const mark = "…"
	cut := n - len(mark)
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + mark
}
