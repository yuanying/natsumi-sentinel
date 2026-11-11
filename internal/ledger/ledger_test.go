package ledger_test

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/yuanying/natsumi-sentinel/internal/audit"
	"github.com/yuanying/natsumi-sentinel/internal/ledger"
	"github.com/yuanying/natsumi-sentinel/internal/routes"
)

type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func open(t *testing.T) (*ledger.Ledger, *clock, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ledger.db")
	c := &clock{now: time.Date(2026, 11, 11, 9, 0, 0, 0, time.UTC)}
	l, err := ledger.Open(path, c.Now)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l, c, path
}

var settings = routes.ApprovalSettings{
	Durations: []time.Duration{time.Hour, 0},
	Once:      10 * time.Minute,
	Pending:   24 * time.Hour,
}

// merge is a held request to merge PR 5, whose target is the repository.
func merge(number string) ledger.Facts {
	return ledger.Facts{
		Source:      "workspace",
		Destination: "api.example.com",
		Method:      "PUT",
		Path:        "/repos/o/r/pulls/" + number + "/merge",
		Operation:   "pulls.merge",
		Params:      []routes.Param{{Name: "owner", Value: "o"}, {Name: "repo", Value: "r"}, {Name: "number", Value: number}},
		Target:      []string{"owner", "repo"},
		Body:        &audit.Body{Text: `{"merge_method":"squash"}`, Size: 25},
		Fingerprint: "fp-merge-" + number,
		Exact:       true,
	}
}

func raw(path string) ledger.Facts {
	return ledger.Facts{
		Source:      "workspace",
		Destination: "api.example.com",
		Method:      "POST",
		Path:        path,
		Fingerprint: "fp-raw-" + path,
		Exact:       true,
	}
}

func choiceIDs(a *ledger.Approval) []string {
	var ids []string
	for _, c := range a.Choices {
		ids = append(ids, c.ID)
	}
	return ids
}

func eq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestAHeldRequestIsAnOpenApprovalWithTheChoicesOfTheSettings(t *testing.T) {
	l, c, _ := open(t)
	ctx := context.Background()
	a, created, err := l.Hold(ctx, merge("5"), settings)
	if err != nil || !created {
		t.Fatalf("Hold = %v, %v", created, err)
	}
	if a.ID == "" || a.State != ledger.Pending || a.Source != "workspace" || len(a.Items) != 1 {
		t.Errorf("approval = %+v", a)
	}
	if !a.Expires.Equal(c.Now().Add(24 * time.Hour)) {
		t.Errorf("expires = %s, want a day on", a.Expires)
	}
	if got := choiceIDs(a); !eq(got, []string{"once", "1h", "forever"}) {
		t.Errorf("choices = %v", got)
	}
	if a.Items[0].TargetText != "owner=o repo=r" || a.Summary == "" {
		t.Errorf("item = %+v, summary = %q", a.Items[0], a.Summary)
	}
}

func TestTheSameRequestHeldAgainIsTheSameApproval(t *testing.T) {
	l, _, _ := open(t)
	ctx := context.Background()
	a, _, _ := l.Hold(ctx, merge("5"), settings)
	b, created, err := l.Hold(ctx, merge("5"), settings)
	if err != nil || created || b.ID != a.ID || b.Requests != 2 {
		t.Errorf("Hold again = %+v, %v, %v; want the same approval, asked twice", b, created, err)
	}
	other, created, _ := l.Hold(ctx, merge("6"), settings)
	if !created || other.ID == a.ID {
		t.Error("another request was put on the same approval")
	}
}

func TestABodyNotSeenWholeIsNotOfferedForOneRequest(t *testing.T) {
	l, _, _ := open(t)
	f := merge("5")
	f.Exact = false
	a, _, err := l.Hold(context.Background(), f, settings)
	if err != nil {
		t.Fatal(err)
	}
	if got := choiceIDs(a); !eq(got, []string{"1h", "forever"}) {
		t.Errorf("choices = %v, want no once", got)
	}
}

func TestAGrantForOneRequestIsUsedOnceAndOnlyByThatRequest(t *testing.T) {
	l, _, _ := open(t)
	ctx := context.Background()
	a, _, _ := l.Hold(ctx, merge("5"), settings)
	got, err := l.Answer(ctx, a.ID, ledger.Answer{Allow: true, Choice: "once"}, nil)
	if err != nil {
		t.Fatalf("Answer: %v", err)
	}
	if got.State != ledger.Allowed || len(got.Grants) != 1 {
		t.Errorf("answered = %+v", got)
	}
	if g, _ := l.Lookup(ctx, merge("6")); g != nil {
		t.Errorf("another request went through on %+v", g)
	}
	changed := merge("5")
	changed.Fingerprint = "fp-merge-5-other-body"
	if g, _ := l.Lookup(ctx, changed); g != nil {
		t.Error("a request with another body went through")
	}
	g, err := l.Lookup(ctx, merge("5"))
	if err != nil || g == nil || g.ID != got.Grants[0] {
		t.Fatalf("Lookup = %+v, %v; want the grant", g, err)
	}
	if g, _ := l.Lookup(ctx, merge("5")); g != nil {
		t.Error("the grant for one request was used twice")
	}
}

func TestAGrantForOneRequestThatIsNotUsedInTimeIsGone(t *testing.T) {
	l, c, _ := open(t)
	ctx := context.Background()
	a, _, _ := l.Hold(ctx, merge("5"), settings)
	if _, err := l.Answer(ctx, a.ID, ledger.Answer{Allow: true, Choice: "once"}, nil); err != nil {
		t.Fatal(err)
	}
	c.advance(11 * time.Minute)
	if g, _ := l.Lookup(ctx, merge("5")); g != nil {
		t.Error("an expired grant was used")
	}
}

func TestAGrantForAWhileCoversTheOperationOnTheTargetUntilItEnds(t *testing.T) {
	l, c, _ := open(t)
	ctx := context.Background()
	a, _, _ := l.Hold(ctx, merge("5"), settings)
	if _, err := l.Answer(ctx, a.ID, ledger.Answer{Allow: true, Choice: "1h"}, nil); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"5", "5", "6"} {
		if g, err := l.Lookup(ctx, merge(n)); err != nil || g == nil {
			t.Errorf("merge %s: Lookup = %v, %v; want the grant", n, g, err)
		}
	}
	elsewhere := merge("7")
	elsewhere.Params[1].Value = "other"
	if g, _ := l.Lookup(ctx, elsewhere); g != nil {
		t.Error("the grant covered another repository")
	}
	otherSource := merge("5")
	otherSource.Source = "server"
	if g, _ := l.Lookup(ctx, otherSource); g != nil {
		t.Error("the grant covered another source")
	}
	c.advance(time.Hour)
	if g, _ := l.Lookup(ctx, merge("5")); g != nil {
		t.Error("the grant outlived its hour")
	}
}

func TestAGrantWithoutAnEndStaysUntilItIsRevoked(t *testing.T) {
	l, c, _ := open(t)
	ctx := context.Background()
	a, _, _ := l.Hold(ctx, merge("5"), settings)
	ans, _ := l.Answer(ctx, a.ID, ledger.Answer{Allow: true, Choice: "forever"}, nil)
	c.advance(10 * 365 * 24 * time.Hour)
	grants, err := l.Grants(ctx)
	if err != nil || len(grants) != 1 || grants[0].Expires != nil {
		t.Fatalf("Grants = %+v, %v", grants, err)
	}
	var recorded *ledger.Grant
	if err := l.Revoke(ctx, ans.Grants[0], func(g *ledger.Grant) error { recorded = g; return nil }); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if recorded == nil || recorded.ID != ans.Grants[0] {
		t.Errorf("the revocation was recorded as %+v", recorded)
	}
	if g, _ := l.Lookup(ctx, merge("5")); g != nil {
		t.Error("a revoked grant was used")
	}
	if err := l.Revoke(ctx, ans.Grants[0], nil); !errors.Is(err, ledger.ErrNotFound) {
		t.Errorf("Revoke again = %v, want ErrNotFound", err)
	}
}

func TestARawOperationIsGrantedForItsDestinationMethodAndPath(t *testing.T) {
	l, _, _ := open(t)
	ctx := context.Background()
	a, _, _ := l.Hold(ctx, raw("/x"), settings)
	if _, err := l.Answer(ctx, a.ID, ledger.Answer{Allow: true, Choice: "1h"}, nil); err != nil {
		t.Fatal(err)
	}
	again := raw("/x")
	again.Fingerprint = "another body"
	if g, _ := l.Lookup(ctx, again); g == nil {
		t.Error("the same method and path did not go through")
	}
	if g, _ := l.Lookup(ctx, raw("/y")); g != nil {
		t.Error("another path went through")
	}
}

func TestAnApprovalIsAnsweredOnceAndOnlyWithAChoiceItOffers(t *testing.T) {
	l, _, _ := open(t)
	ctx := context.Background()
	a, _, _ := l.Hold(ctx, merge("5"), settings)
	if _, err := l.Answer(ctx, a.ID, ledger.Answer{Allow: true, Choice: "30d"}, nil); !errors.Is(err, ledger.ErrBadChoice) {
		t.Errorf("an unoffered choice = %v, want ErrBadChoice", err)
	}
	got, err := l.Answer(ctx, a.ID, ledger.Answer{Allow: false}, nil)
	if err != nil || got.State != ledger.Denied || len(got.Grants) != 0 {
		t.Fatalf("deny = %+v, %v", got, err)
	}
	if _, err := l.Answer(ctx, a.ID, ledger.Answer{Allow: true, Choice: "once"}, nil); !errors.Is(err, ledger.ErrClosed) {
		t.Errorf("a second answer = %v, want ErrClosed", err)
	}
	if _, err := l.Answer(ctx, "ap-nothing", ledger.Answer{Allow: false}, nil); !errors.Is(err, ledger.ErrNotFound) {
		t.Errorf("an unknown approval = %v, want ErrNotFound", err)
	}
	if g, _ := l.Lookup(ctx, merge("5")); g != nil {
		t.Error("a denied request went through")
	}
	// A denied request held again asks again.
	b, created, _ := l.Hold(ctx, merge("5"), settings)
	if !created || b.ID == a.ID {
		t.Error("holding a denied request again did not make a new approval")
	}
}

func TestAnAnswerThatCannotBeRecordedDoesNotTakeEffect(t *testing.T) {
	l, _, _ := open(t)
	ctx := context.Background()
	a, _, _ := l.Hold(ctx, merge("5"), settings)
	_, err := l.Answer(ctx, a.ID, ledger.Answer{Allow: true, Choice: "1h"}, func(*ledger.Approval) error { return errors.New("disk full") })
	if err == nil {
		t.Fatal("Answer succeeded though it was not recorded")
	}
	if g, _ := l.Lookup(ctx, merge("5")); g != nil {
		t.Error("an unrecorded answer gave a grant")
	}
	got, _ := l.Get(ctx, a.ID)
	if got.State != ledger.Pending {
		t.Errorf("state = %s, want still open", got.State)
	}
}

func TestAnApprovalLeftUnansweredIsClosedWhenItsTimeIsUp(t *testing.T) {
	l, c, _ := open(t)
	ctx := context.Background()
	events, cancel := l.Subscribe()
	defer cancel()
	a, _, _ := l.Hold(ctx, merge("5"), settings)
	if e := <-events; e.Type != ledger.EventCreated || e.Approval.ID != a.ID {
		t.Errorf("event = %+v", e)
	}
	c.advance(25 * time.Hour)
	if err := l.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	e := <-events
	if e.Type != ledger.EventClosed || e.Approval.State != ledger.Expired {
		t.Errorf("event = %+v, want it closed as expired", e)
	}
	if _, err := l.Answer(ctx, a.ID, ledger.Answer{Allow: true, Choice: "once"}, nil); !errors.Is(err, ledger.ErrClosed) {
		t.Errorf("answering an expired approval = %v, want ErrClosed", err)
	}
	open, err := l.Approvals(ctx, ledger.Filter{State: ledger.Pending})
	if err != nil || len(open) != 0 {
		t.Errorf("open approvals = %+v, %v", open, err)
	}
}

func TestAnAnswerIsToldToSubscribers(t *testing.T) {
	l, _, _ := open(t)
	ctx := context.Background()
	a, _, _ := l.Hold(ctx, merge("5"), settings)
	events, cancel := l.Subscribe()
	defer cancel()
	if _, err := l.Answer(ctx, a.ID, ledger.Answer{Allow: true, Choice: "1h"}, nil); err != nil {
		t.Fatal(err)
	}
	select {
	case e := <-events:
		if e.Type != ledger.EventClosed || e.Approval.State != ledger.Allowed || e.Approval.Choice != "1h" {
			t.Errorf("event = %+v", e)
		}
	case <-time.After(time.Second):
		t.Fatal("no event")
	}
}

func TestAskingBeforehandIsABundleOfGrantsForOneRequestEach(t *testing.T) {
	l, _, _ := open(t)
	ctx := context.Background()
	items := []ledger.Facts{merge("5"), merge("6")}
	for i := range items {
		items[i].Method, items[i].Path, items[i].Body, items[i].Fingerprint = "", "", nil, ""
	}
	a, err := l.Ask(ctx, "workspace", items, settings)
	if err != nil {
		t.Fatalf("Ask: %v", err)
	}
	if a.Kind != ledger.KindBeforehand || len(a.Items) != 2 || !eq(choiceIDs(a), []string{"once"}) {
		t.Errorf("approval = %+v", a)
	}
	got, err := l.Answer(ctx, a.ID, ledger.Answer{Allow: true, Choice: "once"}, nil)
	if err != nil || len(got.Grants) != 2 {
		t.Fatalf("Answer = %+v, %v", got, err)
	}
	for _, n := range []string{"5", "6"} {
		if g, _ := l.Lookup(ctx, merge(n)); g == nil {
			t.Errorf("merge %s did not go through", n)
		}
		if g, _ := l.Lookup(ctx, merge(n)); g != nil {
			t.Errorf("merge %s went through twice", n)
		}
	}
	if g, _ := l.Lookup(ctx, merge("7")); g != nil {
		t.Error("a merge that was not asked for went through")
	}
}

func TestApprovalsCanBeListedBySourceAndState(t *testing.T) {
	l, _, _ := open(t)
	ctx := context.Background()
	a, _, _ := l.Hold(ctx, merge("5"), settings)
	other := merge("6")
	other.Source = "server"
	_, _, _ = l.Hold(ctx, other, settings)
	c, _, _ := l.Hold(ctx, merge("7"), settings)
	_, _ = l.Answer(ctx, c.ID, ledger.Answer{Allow: false}, nil)

	list, err := l.Approvals(ctx, ledger.Filter{Source: "workspace", State: ledger.Pending})
	if err != nil || len(list) != 1 || list[0].ID != a.ID {
		t.Errorf("open for workspace = %+v, %v", list, err)
	}
	all, _ := l.Approvals(ctx, ledger.Filter{})
	if len(all) != 3 {
		t.Errorf("all = %d, want 3", len(all))
	}
}

func TestTheLedgerIsKeptAcrossOpening(t *testing.T) {
	l, c, path := open(t)
	ctx := context.Background()
	a, _, _ := l.Hold(ctx, merge("5"), settings)
	_, _ = l.Answer(ctx, a.ID, ledger.Answer{Allow: true, Choice: "1h"}, nil)
	_ = l.Close()
	l2, err := ledger.Open(path, c.Now)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l2.Close() }()
	if g, _ := l2.Lookup(ctx, merge("6")); g == nil {
		t.Error("the grant was lost")
	}
}

func TestALedgerInADirectoryThatDoesNotExistDoesNotOpen(t *testing.T) {
	if _, err := ledger.Open(filepath.Join(t.TempDir(), "missing", "ledger.db"), time.Now); err == nil {
		t.Fatal("Open succeeded")
	}
}
