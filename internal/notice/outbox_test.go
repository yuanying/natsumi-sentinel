package notice_test

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/yuanying/natsumi-sentinel/internal/notice"
)

func firstSeen(key string) notice.Notice {
	return notice.Notice{
		Type:    notice.TypeFirstSeen,
		At:      at,
		Labels:  map[string]string{"pair": "destination", "key": key},
		Summary: "first seen: " + key,
	}
}

func TestANoticeIsSentAndOneThatCouldNotBeIsSentAgainLater(t *testing.T) {
	reg := prometheus.NewRegistry()
	sender := newFakeSender()
	sender.setFail(errors.New("connection refused"))
	o := notice.NewOutbox(notice.OutboxConfig{Sender: sender, Registerer: reg, Retry: 20 * time.Millisecond, Logger: slog.New(slog.DiscardHandler)})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go o.Run(ctx)

	o.Put(firstSeen("api.example.com"))
	sender.wait(t)
	wantLines(t, page(t, reg),
		`sentinel_notices_total{type="first-seen"} 1`,
		`sentinel_notices_pending 1`,
	)
	eventually(t, "a send failure counted", func() bool {
		return strings.Contains(page(t, reg), "sentinel_notice_send_failures_total 1\n") || strings.Contains(page(t, reg), "sentinel_notice_send_failures_total 2\n")
	})

	sender.setFail(nil)
	eventually(t, "the notice sent again", func() bool { return len(sender.all()) == 1 })
	if got := sender.all()[0].Labels["key"]; got != "api.example.com" {
		t.Errorf("sent %q", got)
	}
	eventually(t, "nothing pending", func() bool { return o.Pending() == 0 })
	wantLines(t, page(t, reg), `sentinel_notices_pending 0`, `sentinel_notices_dropped_total 0`)
}

func TestWhenTooManyAreWaitingTheOldestAreDroppedAndCounted(t *testing.T) {
	reg := prometheus.NewRegistry()
	sender := newFakeSender()
	o := notice.NewOutbox(notice.OutboxConfig{Sender: sender, Registerer: reg, Max: 2, Logger: slog.New(slog.DiscardHandler)})
	// Not running: nothing is sent, so everything waits.
	o.Put(firstSeen("a.example.com"))
	o.Put(firstSeen("b.example.com"))
	o.Put(firstSeen("c.example.com"))
	if o.Pending() != 2 {
		t.Fatalf("pending = %d, want 2", o.Pending())
	}
	wantLines(t, page(t, reg), `sentinel_notices_dropped_total 1`, `sentinel_notices_pending 2`)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go o.Run(ctx)
	eventually(t, "the two kept sent", func() bool { return len(sender.all()) == 2 })
	if got := sender.all()[0].Labels["key"] + "," + sender.all()[1].Labels["key"]; got != "b.example.com,c.example.com" {
		t.Errorf("sent %s, want the newest two in order", got)
	}
}

func TestEachNoticeIsLoggedAndWithoutASenderThatIsAll(t *testing.T) {
	reg := prometheus.NewRegistry()
	logs := &syncBuffer{}
	o := notice.NewOutbox(notice.OutboxConfig{Registerer: reg, Logger: slog.New(slog.NewJSONHandler(logs, nil))})
	o.Put(firstSeen("api.example.com"))
	if o.Pending() != 0 {
		t.Errorf("pending = %d without a sender, want 0", o.Pending())
	}
	if !strings.Contains(logs.String(), "first seen: api.example.com") {
		t.Errorf("logs = %q, want the notice", logs.String())
	}
	wantLines(t, page(t, reg),
		`sentinel_notices_total{type="first-seen"} 1`,
		`sentinel_notice_sender_configured 0`,
	)
}

func TestWhatIsStillWaitingIsTriedOnceMoreWhenStopping(t *testing.T) {
	sender := newFakeSender()
	o := notice.NewOutbox(notice.OutboxConfig{Sender: sender, Registerer: prometheus.NewRegistry(), Retry: time.Hour, Logger: slog.New(slog.DiscardHandler)})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	o.Put(firstSeen("api.example.com"))
	o.Run(ctx)
	if len(sender.all()) != 1 {
		t.Errorf("sent %d when stopping, want 1", len(sender.all()))
	}
}
