package notice

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/yuanying/natsumi-sentinel/internal/audit"
)

// DayLog is what the summary is read from.
type DayLog interface {
	Day(ctx context.Context, from, to time.Time) (*audit.Day, error)
	SeenBetween(ctx context.Context, from, to time.Time) ([]audit.Seen, error)
}

// SummaryConfig is what a Summarizer needs.
type SummaryConfig struct {
	Log    DayLog
	Outbox *Outbox
	// At is the time of day of the summary, HH:MM, in Location. The
	// summary covers the day up to it.
	At       string
	Location *time.Location
	// Lines is how many lines each part of the summary may have; the rest
	// are counted. Defaults to 30.
	Lines      int
	Logger     *slog.Logger
	Registerer prometheus.Registerer
	Now        func() time.Time
	// Wait waits until the time given, and reports false if ctx was done
	// first. Defaults to a timer.
	Wait func(ctx context.Context, until time.Time) bool
}

// Summarizer puts the daily summary in the outbox at the set time.
type Summarizer struct {
	cfg          SummaryConfig
	hour, minute int
	failures     prometheus.Counter
}

// NewSummarizer checks the time of day and makes a Summarizer.
func NewSummarizer(cfg SummaryConfig) (*Summarizer, error) {
	h, m, err := parseClock(cfg.At)
	if err != nil {
		return nil, err
	}
	if cfg.Location == nil {
		cfg.Location = time.UTC
	}
	if cfg.Lines <= 0 {
		cfg.Lines = 30
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Wait == nil {
		cfg.Wait = wait
	}
	s := &Summarizer{cfg: cfg, hour: h, minute: m, failures: prometheus.NewCounter(prometheus.CounterOpts{
		Name: "sentinel_notice_summary_failures_total",
		Help: "Daily summaries that could not be made from the records.",
	})}
	if cfg.Registerer != nil {
		cfg.Registerer.MustRegister(s.failures)
	}
	return s, nil
}

func parseClock(s string) (int, int, error) {
	hh, mm, ok := strings.Cut(s, ":")
	h, herr := strconv.Atoi(hh)
	m, merr := strconv.Atoi(mm)
	if !ok || len(hh) != 2 || len(mm) != 2 || herr != nil || merr != nil || h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, 0, fmt.Errorf("the time of the summary %q is not HH:MM", s)
	}
	return h, m, nil
}

// Next is the first time of the summary after now.
func (s *Summarizer) Next(now time.Time) time.Time {
	local := now.In(s.cfg.Location)
	next := time.Date(local.Year(), local.Month(), local.Day(), s.hour, s.minute, 0, 0, s.cfg.Location)
	if !next.After(now) {
		next = time.Date(local.Year(), local.Month(), local.Day()+1, s.hour, s.minute, 0, 0, s.cfg.Location)
	}
	return next
}

// Run puts a summary at each time of the summary, covering the day before
// it, until ctx is done. A summary whose time passes while the gate is
// not running is not made later.
func (s *Summarizer) Run(ctx context.Context) {
	after := s.cfg.Now()
	for {
		at := s.Next(after)
		if !s.cfg.Wait(ctx, at) {
			return
		}
		from := time.Date(at.Year(), at.Month(), at.Day()-1, s.hour, s.minute, 0, 0, s.cfg.Location)
		n, err := s.Build(ctx, from, at)
		if err != nil {
			s.failures.Inc()
			s.cfg.Logger.Error("the daily summary could not be made", "from", from, "to", at, "error", err)
		} else {
			s.cfg.Outbox.Put(n)
		}
		after = at
	}
}

func wait(ctx context.Context, until time.Time) bool {
	t := time.NewTimer(time.Until(until))
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// Build makes the summary of the records from from up to to.
func (s *Summarizer) Build(ctx context.Context, from, to time.Time) (Notice, error) {
	if s.cfg.Log == nil {
		return Notice{}, errors.New("no audit log to summarize")
	}
	day, err := s.cfg.Log.Day(ctx, from, to)
	if err != nil {
		return Notice{}, err
	}
	seen, err := s.cfg.Log.SeenBetween(ctx, from, to)
	if err != nil {
		return Notice{}, err
	}

	var writes, asked, denied int64
	for _, w := range day.Writes {
		writes += w.Count
	}
	for _, r := range day.Asks {
		asked += r.Count
	}
	for _, r := range day.Denials {
		denied += r.Count
	}
	counts := fmt.Sprintf("%s, %s, %d asked, %d denied, %s", plural(writes, "write"), plural(int64(len(seen)), "new pair"),
		asked, denied, plural(int64(len(day.Answers)), "answer"))

	var b strings.Builder
	layout := "2006-01-02 15:04 MST"
	fmt.Fprintf(&b, "From %s to %s: %s.\n", from.In(s.cfg.Location).Format(layout), to.In(s.cfg.Location).Format(layout), counts)

	fmt.Fprintf(&b, "\nWrites let through, by destination and operation: %s\n", plural(writes, "write"))
	s.lines(&b, len(day.Writes), func(i int) string {
		w := day.Writes[i]
		return fmt.Sprintf("%d  %s", w.Count, strings.Join(nonEmpty(w.Name, w.Operation, w.Method), " "))
	})
	fmt.Fprintf(&b, "\nSeen for the first time: %s\n", plural(int64(len(seen)), "new pair"))
	s.lines(&b, len(seen), func(i int) string {
		return seen[i].Pair + "  " + seen[i].Key
	})
	fmt.Fprintf(&b, "\nAsked the owner: %d asked\n", asked)
	s.lines(&b, len(day.Asks), func(i int) string { return refusalLine(day.Asks[i]) })
	fmt.Fprintf(&b, "\nDenied: %d denied\n", denied)
	s.lines(&b, len(day.Denials), func(i int) string { return refusalLine(day.Denials[i]) })
	fmt.Fprintf(&b, "\nAnswers of the owner's: %s\n", plural(int64(len(day.Answers)), "answer"))
	s.lines(&b, len(day.Answers), func(i int) string { return s.answerLine(day.Answers[i]) })

	return Notice{
		Type:        TypeDailySummary,
		At:          to,
		Labels:      map[string]string{"day": from.In(s.cfg.Location).Format("2006-01-02")},
		Summary:     "Sentinel's day: " + counts,
		Description: b.String(),
	}, nil
}

func refusalLine(r audit.RefusalCount) string {
	what := strings.Join(nonEmpty(string(r.Kind), r.Name, r.Operation, r.Target, r.Method, r.Path), " ")
	return fmt.Sprintf("%d  %s: %s", r.Count, what, r.Reason)
}

// answerLine tells one answer. The reason of a revocation is not told: it
// can name the request a grant of one request was for, query and all.
func (s *Summarizer) answerLine(a audit.Answer) string {
	what := strings.Join(nonEmpty(a.Name, a.Operation, a.Target), " ")
	if a.Operation == "" {
		what = strings.Join(nonEmpty(a.Name, a.Method, a.Path), " ")
	}
	var head string
	switch {
	case a.Verdict == audit.Allow && a.Approval == "":
		// A grant given from the list of refused names.
		head = "allowed " + a.Grant
	case a.Verdict == audit.Allow:
		head = "allowed " + a.Approval
	case a.Grant != "" && a.Approval == "":
		head = "revoked " + a.Grant
	case a.Grant != "":
		head = "revoked " + a.Grant + " of " + a.Approval
	default:
		head = "denied " + a.Approval
	}
	line := strings.Join(nonEmpty(a.Time.In(s.cfg.Location).Format("15:04 MST"), a.Source, head+": "+what), "  ")
	if a.Verdict == audit.Allow {
		line += "; " + a.Reason
	}
	return line
}

// lines writes up to Lines lines of a part, and how many were left out.
func (s *Summarizer) lines(b *strings.Builder, n int, line func(int) string) {
	for i := range min(n, s.cfg.Lines) {
		b.WriteString("  " + clip(line(i), maxLabel) + "\n")
	}
	if n > s.cfg.Lines {
		fmt.Fprintf(b, "  and %d more\n", n-s.cfg.Lines)
	}
}

func plural(n int64, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}

func nonEmpty(parts ...string) []string {
	var out []string
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
