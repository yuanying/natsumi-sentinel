package notice_test

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/yuanying/natsumi-sentinel/internal/audit"
	"github.com/yuanying/natsumi-sentinel/internal/notice"
)

func TestTheClockOfTheSummaryIsHoursAndMinutes(t *testing.T) {
	for _, bad := range []string{"", "9", "24:00", "09:60", "9:5:0", "ab:cd", "-1:00"} {
		if _, err := notice.NewSummarizer(notice.SummaryConfig{At: bad, Location: time.UTC}); err == nil {
			t.Errorf("NewSummarizer(At: %q) = nil error", bad)
		}
	}
}

func TestTheNextSummaryIsAtTheSetTimeInTheSetZone(t *testing.T) {
	tokyo := time.FixedZone("JST", 9*3600)
	s, err := notice.NewSummarizer(notice.SummaryConfig{At: "09:00", Location: tokyo})
	if err != nil {
		t.Fatal(err)
	}
	for now, want := range map[time.Time]time.Time{
		time.Date(2026, 11, 11, 8, 0, 0, 0, tokyo):  time.Date(2026, 11, 11, 9, 0, 0, 0, tokyo),
		time.Date(2026, 11, 11, 9, 0, 0, 0, tokyo):  time.Date(2026, 11, 12, 9, 0, 0, 0, tokyo),
		time.Date(2026, 11, 11, 23, 0, 0, 0, tokyo): time.Date(2026, 11, 12, 9, 0, 0, 0, tokyo),
		// 23:30 UTC is 08:30 the next day in Tokyo.
		time.Date(2026, 11, 11, 23, 30, 0, 0, time.UTC): time.Date(2026, 11, 12, 9, 0, 0, 0, tokyo),
	} {
		if got := s.Next(now); !got.Equal(want) {
			t.Errorf("Next(%v) = %v, want %v", now, got, want)
		}
	}
}

func dayLog(t *testing.T) *audit.Log {
	t.Helper()
	l := openLog(t)
	ctx := context.Background()
	write := func(rec audit.Record) {
		if err := l.Write(ctx, &rec); err != nil {
			t.Fatal(err)
		}
	}
	for i := range 3 {
		write(audit.Record{Time: at.Add(time.Duration(i) * time.Minute), Kind: audit.KindHTTP, Name: "api.example.com", Method: "POST", Path: fmt.Sprintf("/repos/o/r/issues/%d/comments", i), Verdict: audit.Allow})
	}
	write(audit.Record{Time: at, Kind: audit.KindHTTP, Name: "cluster.example.com", Method: "PATCH", Path: "/apis/apps/v1/namespaces/a/deployments/b", Verdict: audit.Allow})
	write(audit.Record{Time: at, Kind: audit.KindHTTP, Name: "api.example.com", Method: "DELETE", Path: "/repos/o/r", Verdict: audit.Deny, Reason: "the destination's default is deny"})
	write(audit.Record{Time: at, Kind: audit.KindDNS, Name: "made-up.example.net", Verdict: audit.Deny, Reason: "not an open destination in the routing table"})
	if _, err := l.MarkSeen(ctx, audit.Seen{Pair: notice.PairDestination, Key: "cluster.example.com", First: at, Record: 4}); err != nil {
		t.Fatal(err)
	}
	return l
}

func TestTheSummaryTellsTheDaysWritesNewPairsAndRefusals(t *testing.T) {
	s, err := notice.NewSummarizer(notice.SummaryConfig{Log: dayLog(t), At: "00:00", Location: time.UTC})
	if err != nil {
		t.Fatal(err)
	}
	from, to := at.Truncate(24*time.Hour), at.Truncate(24*time.Hour).AddDate(0, 0, 1)
	n, err := s.Build(context.Background(), from, to)
	if err != nil {
		t.Fatal(err)
	}
	if n.Type != notice.TypeDailySummary || n.Labels["day"] != "2026-11-11" || !n.At.Equal(to) {
		t.Errorf("notice = %+v", n)
	}
	for _, want := range []string{
		"4 writes",
		"3  api.example.com POST",
		"1  cluster.example.com PATCH",
		"1 new pair",
		"destination  cluster.example.com",
		"2 refused",
		"1  deny http api.example.com DELETE /repos/o/r: the destination's default is deny",
		"1  deny dns made-up.example.net: not an open destination in the routing table",
	} {
		if !strings.Contains(n.Description, want) {
			t.Errorf("the summary does not say %q:\n%s", want, n.Description)
		}
	}
	if !strings.Contains(n.Summary, "4 writes") {
		t.Errorf("summary = %q", n.Summary)
	}
}

func TestALongSummaryIsCutAndSaysHowMuchWasLeftOut(t *testing.T) {
	s, err := notice.NewSummarizer(notice.SummaryConfig{Log: dayLog(t), At: "00:00", Location: time.UTC, Lines: 1})
	if err != nil {
		t.Fatal(err)
	}
	n, err := s.Build(context.Background(), at.Truncate(24*time.Hour), at.Truncate(24*time.Hour).AddDate(0, 0, 1))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(n.Description, "cluster.example.com PATCH") || !strings.Contains(n.Description, "and 1 more") {
		t.Errorf("the summary was not cut to one line a section:\n%s", n.Description)
	}
}

func TestTheSummaryIsPutAtEachSetTimeForTheDayBefore(t *testing.T) {
	reg := prometheus.NewRegistry()
	sender := newFakeSender()
	out := notice.NewOutbox(notice.OutboxConfig{Sender: sender, Registerer: reg, Logger: slog.New(slog.DiscardHandler)})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go out.Run(ctx)

	var waited []time.Time
	s, err := notice.NewSummarizer(notice.SummaryConfig{
		Log: dayLog(t), Outbox: out, At: "00:00", Location: time.UTC, Registerer: reg,
		Now: func() time.Time { return at },
		Wait: func(ctx context.Context, until time.Time) bool {
			waited = append(waited, until)
			return len(waited) < 2
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	s.Run(ctx)
	eventually(t, "the summary sent", func() bool { return len(sender.all()) == 1 })
	n := sender.all()[0]
	if n.Labels["day"] != "2026-11-11" || !strings.Contains(n.Description, "4 writes") {
		t.Errorf("summary = %+v", n)
	}
	if !waited[0].Equal(time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("waited until %v", waited[0])
	}
}
