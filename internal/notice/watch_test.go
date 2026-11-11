package notice_test

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/yuanying/natsumi-sentinel/internal/audit"
	"github.com/yuanying/natsumi-sentinel/internal/notice"
	"github.com/yuanying/natsumi-sentinel/internal/observe"
)

func TestAPairIsToldTheFirstTimeOnlyAndKeptInTheLog(t *testing.T) {
	log := openLog(t)
	reg := prometheus.NewRegistry()
	sender := newFakeSender()
	out := notice.NewOutbox(notice.OutboxConfig{Sender: sender, Registerer: reg, Logger: slog.New(slog.DiscardHandler)})
	w := notice.NewWatcher(notice.WatcherConfig{Log: log, Outbox: out, Registerer: reg, Logger: slog.New(slog.DiscardHandler)})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go out.Run(ctx)
	go w.Run(ctx)

	post := audit.Record{ID: 5, Time: at, Source: "workspace", Kind: audit.KindHTTP, Name: "api.example.com", Method: "POST", Path: "/repos/o/r/issues", Verdict: audit.Allow}
	// Begun, not finished: not yet.
	w.Observe(observe.Event{Stage: observe.Begin, Record: post})
	// Not written: it did not go through.
	w.Observe(observe.Event{Stage: observe.Write, Err: errors.New("disk full"), Record: post})
	w.Observe(observe.Event{Stage: observe.Finish, Record: post})
	post.ID = 6
	w.Observe(observe.Event{Stage: observe.Finish, Record: post})

	eventually(t, "the two pairs told", func() bool { return len(sender.all()) == 2 })
	got := sender.all()
	if got[0].Labels["pair"] != notice.PairDestination || got[1].Labels["pair"] != notice.PairWrite {
		t.Fatalf("told %+v", got)
	}
	if got[1].Labels["key"] != "api.example.com POST /repos/o/r/issues" || got[1].Labels["source"] != "workspace" {
		t.Errorf("the write told = %+v", got[1].Labels)
	}
	if !got[1].At.Equal(at) || got[1].Summary == "" || got[1].Description == "" {
		t.Errorf("the write told = %+v", got[1])
	}

	seen, err := log.SeenBetween(ctx, at, at.AddDate(0, 0, 1))
	if err != nil || len(seen) != 2 || seen[0].Record != 5 {
		t.Errorf("kept %+v, %v; want the two pairs from record 5", seen, err)
	}
}

func TestRecordsThatCannotBeLookedAtAreCounted(t *testing.T) {
	reg := prometheus.NewRegistry()
	out := notice.NewOutbox(notice.OutboxConfig{Registerer: reg, Logger: slog.New(slog.DiscardHandler)})
	w := notice.NewWatcher(notice.WatcherConfig{Log: openLog(t), Outbox: out, Registerer: reg, Buffer: 1, Logger: slog.New(slog.DiscardHandler)})
	rec := audit.Record{Kind: audit.KindDNS, Treatment: "deny", Name: "made-up.example.net", Verdict: audit.Deny}
	// Not running, with room for one.
	w.Observe(observe.Event{Stage: observe.Write, Record: rec})
	w.Observe(observe.Event{Stage: observe.Write, Record: rec})
	w.Observe(observe.Event{Stage: observe.Write, Record: rec})
	wantLines(t, page(t, reg), `sentinel_notice_records_unchecked_total 2`)
}
