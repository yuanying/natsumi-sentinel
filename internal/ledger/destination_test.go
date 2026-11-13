package ledger_test

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/yuanying/natsumi-sentinel/internal/ledger"
)

func dest(name string) ledger.Facts {
	return ledger.Facts{Destination: name}
}

func optionIDs(os []ledger.Option) []string {
	var ids []string
	for _, o := range os {
		ids = append(ids, o.ID)
	}
	return ids
}

func askDest(t *testing.T, l *ledger.Ledger, names ...string) *ledger.Approval {
	t.Helper()
	var items []ledger.Facts
	for _, n := range names {
		items = append(items, dest(n))
	}
	a, err := l.AskDestinations(context.Background(), "workspace", items, settings, nil)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestDestinationsAskedForAreOneApprovalWithTimedChoicesAndOptions(t *testing.T) {
	l, _, _ := open(t)
	a := askDest(t, l, "a.b.example.com")
	if a.Kind != ledger.KindDestination || a.State != ledger.Pending {
		t.Errorf("kind %s, state %s", a.Kind, a.State)
	}
	if got := choiceIDs(a); !eq(got, []string{"1h", "forever"}) {
		t.Errorf("choices = %v", got)
	}
	for _, c := range a.Choices {
		if c.Scope != ledger.ScopeTimed {
			t.Errorf("choice %s is %s", c.ID, c.Scope)
		}
	}
	if a.Options == nil {
		t.Fatal("no options")
	}
	if got := optionIDs(a.Options.Unit); !eq(got, []string{"name", "domain:b.example.com", "domain:example.com"}) {
		t.Errorf("unit = %v", got)
	}
	if got := optionIDs(a.Options.Handling); !eq(got, []string{"inspect", "passthrough"}) {
		t.Errorf("handling = %v", got)
	}
	if got := optionIDs(a.Options.Access); !eq(got, []string{"read", "readwrite"}) {
		t.Errorf("access = %v", got)
	}
	for _, o := range slices.Concat(a.Options.Unit, a.Options.Handling, a.Options.Access) {
		if o.Label == "" {
			t.Errorf("option %s has no label", o.ID)
		}
	}
	if !strings.Contains(a.Summary, "a.b.example.com") {
		t.Errorf("summary = %q", a.Summary)
	}
}

func TestADomainFoundByTheDefaultRuleIsToldSo(t *testing.T) {
	l, _, _ := open(t)
	a := askDest(t, l, "a.b.c.example")
	if got := optionIDs(a.Options.Unit); !eq(got, []string{"name", "domain:b.c.example", "domain:c.example"}) {
		t.Fatalf("unit = %v", got)
	}
	if label := a.Options.Unit[2].Label; !strings.Contains(label, "public suffix list") {
		t.Errorf("label = %q", label)
	}
	if label := a.Options.Unit[0].Label; strings.Contains(label, "public suffix list") {
		t.Errorf("label of the name = %q", label)
	}
}

func TestThePassthroughOptionSaysReadsAndWritesGoThroughUnseen(t *testing.T) {
	l, _, _ := open(t)
	a := askDest(t, l, "example.com")
	label := a.Options.Handling[1].Label
	if !strings.Contains(label, "reads and writes") || !strings.Contains(label, "not seen") {
		t.Errorf("label = %q", label)
	}
}

func TestSeveralNamesAreOfferedOnlyTheDomainsCoveringThemAll(t *testing.T) {
	l, _, _ := open(t)
	a := askDest(t, l, "a.x.example.com", "b.x.example.com", "c.example.com")
	if got := optionIDs(a.Options.Unit); !eq(got, []string{"name", "domain:example.com"}) {
		t.Errorf("unit = %v", got)
	}
	if b := askDest(t, l, "a.example.com", "b.example.net"); !eq(optionIDs(b.Options.Unit), []string{"name"}) {
		t.Errorf("unit = %v", optionIDs(b.Options.Unit))
	}
}

func TestAllowedWithoutOptionsADestinationIsTheNameOnlyOpenedAndReadOnly(t *testing.T) {
	l, _, _ := open(t)
	a := askDest(t, l, "docs.example.com", "cdn.example.net")
	got, err := l.Answer(context.Background(), a.ID, ledger.Answer{Allow: true, Choice: "1h"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Grants) != 2 {
		t.Fatalf("grants = %v", got.Grants)
	}
	gs, _ := l.Grants(context.Background())
	if len(gs) != 2 {
		t.Fatalf("grants listed: %d", len(gs))
	}
	g := gs[0]
	if g.Name != "docs.example.com" {
		g = gs[1]
	}
	if g.Kind != ledger.GrantDestination || g.Name != "docs.example.com" || g.Unit != ledger.UnitName ||
		g.Handling != ledger.Inspect || g.Access != ledger.Read || g.Approval != a.ID || g.Expires == nil || g.Scope != ledger.ScopeTimed {
		t.Errorf("grant = %+v", g)
	}
	if g.Destination != "" || g.Operation != "" {
		t.Errorf("a destination grant has destination %q, operation %q", g.Destination, g.Operation)
	}
	if !strings.Contains(g.Summary, "docs.example.com") || !strings.Contains(g.Summary, "1h") {
		t.Errorf("summary = %q", g.Summary)
	}
}

func TestTheOptionsChosenShapeTheGrants(t *testing.T) {
	l, _, _ := open(t)
	a := askDest(t, l, "a.b.example.com")
	_, err := l.Answer(context.Background(), a.ID, ledger.Answer{Allow: true, Choice: "forever",
		Options: &ledger.OptionAnswer{Unit: "domain:example.com", Handling: "inspect", Access: "readwrite"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	gs, _ := l.Grants(context.Background())
	g := gs[0]
	if g.Unit != ledger.UnitDomain || g.Name != "example.com" || g.Access != ledger.ReadWrite || g.Expires != nil {
		t.Errorf("grant = %+v", g)
	}
}

func TestAPassthroughGrantHasNoAccess(t *testing.T) {
	l, _, _ := open(t)
	a := askDest(t, l, "k8s.example.com")
	_, err := l.Answer(context.Background(), a.ID, ledger.Answer{Allow: true, Choice: "1h",
		Options: &ledger.OptionAnswer{Handling: "passthrough", Access: "read"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	gs, _ := l.Grants(context.Background())
	if g := gs[0]; g.Handling != ledger.Passthrough || g.Access != "" || !strings.Contains(g.Summary, "not seen") {
		t.Errorf("grant = %+v", g)
	}
}

func TestOptionsNotOfferedAreRefused(t *testing.T) {
	l, _, _ := open(t)
	a := askDest(t, l, "a.example.com")
	for _, opt := range []ledger.OptionAnswer{{Unit: "domain:com"}, {Unit: "domain:other.example"}, {Handling: "open"}, {Access: "write"}} {
		if _, err := l.Answer(context.Background(), a.ID, ledger.Answer{Allow: true, Choice: "1h", Options: &opt}, nil); !errors.Is(err, ledger.ErrBadChoice) {
			t.Errorf("%+v: err = %v", opt, err)
		}
	}
	if _, err := l.Answer(context.Background(), a.ID, ledger.Answer{Allow: true, Choice: "once"}, nil); !errors.Is(err, ledger.ErrBadChoice) {
		t.Errorf("once: err = %v", err)
	}
}

func TestOptionsOnAnotherApprovalAreRefused(t *testing.T) {
	l, _, _ := open(t)
	a, _, err := l.Hold(context.Background(), merge("5"), settings)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Answer(context.Background(), a.ID, ledger.Answer{Allow: true, Choice: "1h", Options: &ledger.OptionAnswer{}}, nil); !errors.Is(err, ledger.ErrBadChoice) {
		t.Errorf("err = %v", err)
	}
}

// grant gives a destination grant directly, through an approval.
func grant(t *testing.T, l *ledger.Ledger, name, choice string, opt ledger.OptionAnswer) *ledger.Grant {
	t.Helper()
	a := askDest(t, l, name)
	got, err := l.Answer(context.Background(), a.ID, ledger.Answer{Allow: true, Choice: choice, Options: &opt}, nil)
	if err != nil {
		t.Fatal(err)
	}
	gs, _ := l.Grants(context.Background())
	for _, g := range gs {
		if g.ID == got.Grants[0] {
			return g
		}
	}
	t.Fatal("the grant is not listed")
	return nil
}

func lookupDest(t *testing.T, l *ledger.Ledger, source, name string) *ledger.Grant {
	t.Helper()
	g, err := l.LookupDestination(context.Background(), source, name)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func TestADestinationGrantForANameCoversThatNameOnlyFromItsSource(t *testing.T) {
	l, _, _ := open(t)
	g := grant(t, l, "docs.example.com", "1h", ledger.OptionAnswer{})
	if got := lookupDest(t, l, "workspace", "docs.example.com"); got == nil || got.ID != g.ID {
		t.Errorf("lookup = %+v", got)
	}
	for _, n := range []string{"example.com", "a.docs.example.com", "docs.example.net"} {
		if got := lookupDest(t, l, "workspace", n); got != nil {
			t.Errorf("%s: covered by %s", n, got.ID)
		}
	}
	if got := lookupDest(t, l, "other", "docs.example.com"); got != nil {
		t.Errorf("another source: covered by %s", got.ID)
	}
}

func TestADestinationGrantForADomainCoversItAndTheNamesUnderIt(t *testing.T) {
	l, _, _ := open(t)
	grant(t, l, "a.example.com", "1h", ledger.OptionAnswer{Unit: "domain:example.com"})
	for _, n := range []string{"example.com", "a.example.com", "x.y.example.com"} {
		if lookupDest(t, l, "workspace", n) == nil {
			t.Errorf("%s is not covered", n)
		}
	}
	if lookupDest(t, l, "workspace", "badexample.com") != nil {
		t.Error("badexample.com is covered")
	}
}

func TestADestinationGrantEndsWithItsTimeAndWithRevoking(t *testing.T) {
	l, c, _ := open(t)
	grant(t, l, "a.example.com", "1h", ledger.OptionAnswer{})
	c.advance(time.Hour)
	if lookupDest(t, l, "workspace", "a.example.com") != nil {
		t.Error("covered after its time")
	}
	g := grant(t, l, "b.example.com", "forever", ledger.OptionAnswer{})
	if err := l.Revoke(context.Background(), g.ID, nil); err != nil {
		t.Fatal(err)
	}
	if lookupDest(t, l, "workspace", "b.example.com") != nil {
		t.Error("covered after it was revoked")
	}
}

func TestOfSeveralDestinationGrantsTheOpenedReadWriteNameOnlyOldestComesFirst(t *testing.T) {
	l, c, _ := open(t)
	pass := grant(t, l, "a.example.com", "1h", ledger.OptionAnswer{Handling: "passthrough"})
	c.advance(time.Second)
	if got := lookupDest(t, l, "workspace", "a.example.com"); got.ID != pass.ID {
		t.Fatalf("got %s", got.ID)
	}
	read := grant(t, l, "a.example.com", "1h", ledger.OptionAnswer{Unit: "domain:example.com"})
	c.advance(time.Second)
	if got := lookupDest(t, l, "workspace", "a.example.com"); got.ID != read.ID {
		t.Errorf("inspect is not before passthrough: got %s", got.ID)
	}
	rw := grant(t, l, "a.example.com", "1h", ledger.OptionAnswer{Unit: "domain:example.com", Access: "readwrite"})
	c.advance(time.Second)
	if got := lookupDest(t, l, "workspace", "a.example.com"); got.ID != rw.ID {
		t.Errorf("readwrite is not before read: got %s", got.ID)
	}
	name := grant(t, l, "a.example.com", "1h", ledger.OptionAnswer{Access: "readwrite"})
	c.advance(time.Second)
	if got := lookupDest(t, l, "workspace", "a.example.com"); got.ID != name.ID {
		t.Errorf("name is not before domain: got %s", got.ID)
	}
	grant(t, l, "a.example.com", "1h", ledger.OptionAnswer{Access: "readwrite"})
	if got := lookupDest(t, l, "workspace", "a.example.com"); got.ID != name.ID {
		t.Errorf("the older is not first: got %s", got.ID)
	}
}

func TestADestinationGrantIsNoOperationGrant(t *testing.T) {
	l, _, _ := open(t)
	grant(t, l, "api.example.com", "forever", ledger.OptionAnswer{Access: "readwrite"})
	g, err := l.Lookup(context.Background(), raw("/anything"))
	if err != nil || g != nil {
		t.Errorf("lookup = %+v, %v", g, err)
	}
}

func TestOperationGrantsAreOfKindOperation(t *testing.T) {
	l, _, _ := open(t)
	a, _, _ := l.Hold(context.Background(), merge("5"), settings)
	if _, err := l.Answer(context.Background(), a.ID, ledger.Answer{Allow: true, Choice: "1h"}, nil); err != nil {
		t.Fatal(err)
	}
	gs, _ := l.Grants(context.Background())
	if gs[0].Kind != ledger.GrantOperation {
		t.Errorf("kind = %q", gs[0].Kind)
	}
}

func remember(t *testing.T, l *ledger.Ledger, source, name string) int {
	t.Helper()
	n, err := l.RememberRefused(context.Background(), source, name)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func refused(t *testing.T, l *ledger.Ledger, source string) []ledger.RefusedName {
	t.Helper()
	got, err := l.RefusedNames(context.Background(), ledger.RefusedFilter{Source: source})
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestARefusedNameIsRememberedWithWhenAndHowOften(t *testing.T) {
	l, c, _ := open(t)
	start := c.Now()
	remember(t, l, "workspace", "a.b.example.com")
	c.advance(time.Minute)
	remember(t, l, "workspace", "a.b.example.com")
	got := refused(t, l, "workspace")
	if len(got) != 1 {
		t.Fatalf("got %+v", got)
	}
	r := got[0]
	if r.Name != "a.b.example.com" || r.Source != "workspace" || r.Count != 2 || !r.First.Equal(start) || !r.Last.Equal(start.Add(time.Minute)) || r.Domain != "example.com" {
		t.Errorf("refused = %+v", r)
	}
	if len(refused(t, l, "other")) != 0 {
		t.Error("another source has it")
	}
}

func TestRefusedNamesAreListedNewestFirst(t *testing.T) {
	l, c, _ := open(t)
	for _, n := range []string{"a.example.com", "b.example.com", "c.example.com"} {
		remember(t, l, "workspace", n)
		c.advance(time.Second)
	}
	remember(t, l, "workspace", "a.example.com")
	var names []string
	for _, r := range refused(t, l, "workspace") {
		names = append(names, r.Name)
	}
	if !eq(names, []string{"a.example.com", "c.example.com", "b.example.com"}) {
		t.Errorf("names = %v", names)
	}
	got, _ := l.RefusedNames(context.Background(), ledger.RefusedFilter{Source: "workspace", Since: c.Now().Add(-1500 * time.Millisecond)})
	if len(got) != 2 {
		t.Errorf("since: %d", len(got))
	}
}

func TestRefusedNamesBeyondTheLimitAreDroppedOldestFirst(t *testing.T) {
	l, c, _ := open(t)
	l.SetRefusedLimits(2, 30*24*time.Hour)
	remember(t, l, "workspace", "a.example.com")
	c.advance(time.Second)
	remember(t, l, "workspace", "b.example.com")
	c.advance(time.Second)
	if n := remember(t, l, "workspace", "c.example.com"); n != 1 {
		t.Errorf("dropped %d", n)
	}
	remember(t, l, "other", "d.example.com")
	var names []string
	for _, r := range refused(t, l, "workspace") {
		names = append(names, r.Name)
	}
	if !eq(names, []string{"c.example.com", "b.example.com"}) {
		t.Errorf("names = %v", names)
	}
	if n, _ := l.CountRefused(context.Background()); n != 3 {
		t.Errorf("count = %d", n)
	}
}

func TestRefusedNamesNotSeenForLongAreSweptAway(t *testing.T) {
	l, c, _ := open(t)
	l.SetRefusedLimits(1000, 24*time.Hour)
	remember(t, l, "workspace", "a.example.com")
	c.advance(23 * time.Hour)
	remember(t, l, "workspace", "b.example.com")
	c.advance(2 * time.Hour)
	if err := l.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := refused(t, l, "workspace"); len(got) != 1 || got[0].Name != "b.example.com" {
		t.Errorf("got %+v", got)
	}
}

func TestAGrantTakesTheNamesItCoversOffTheRefusedList(t *testing.T) {
	l, _, _ := open(t)
	for _, n := range []string{"a.example.com", "b.example.com", "example.net"} {
		remember(t, l, "workspace", n)
	}
	remember(t, l, "other", "a.example.com")
	grant(t, l, "a.example.com", "1h", ledger.OptionAnswer{Unit: "domain:example.com"})
	if got := refused(t, l, "workspace"); len(got) != 1 || got[0].Name != "example.net" {
		t.Errorf("got %+v", got)
	}
	if got := refused(t, l, "other"); len(got) != 1 {
		t.Errorf("another source's: %+v", got)
	}
}

func TestARefusedNameIsGrantedFromTheList(t *testing.T) {
	l, _, _ := open(t)
	remember(t, l, "workspace", "a.b.example.com")
	var recorded *ledger.Grant
	g, err := l.GrantRefused(context.Background(), ledger.RefusedGrant{
		Source: "workspace", Name: "a.b.example.com", Settings: settings, Choice: "1h",
		Options: ledger.OptionAnswer{Unit: "domain:b.example.com", Handling: "passthrough"},
	}, func(g *ledger.Grant) error { recorded = g; return nil })
	if err != nil {
		t.Fatal(err)
	}
	if recorded == nil || recorded.ID != g.ID {
		t.Error("not recorded")
	}
	if g.Approval != "" || g.Name != "b.example.com" || g.Unit != ledger.UnitDomain || g.Handling != ledger.Passthrough || g.Expires == nil {
		t.Errorf("grant = %+v", g)
	}
	if len(refused(t, l, "workspace")) != 0 {
		t.Error("still in the list")
	}
	if lookupDest(t, l, "workspace", "c.b.example.com") == nil {
		t.Error("not in effect")
	}
}

func TestOnlyANameInTheListIsGrantedFromIt(t *testing.T) {
	l, _, _ := open(t)
	remember(t, l, "workspace", "a.example.com")
	for _, rg := range []ledger.RefusedGrant{
		{Source: "workspace", Name: "b.example.com", Settings: settings, Choice: "1h"},
		{Source: "other", Name: "a.example.com", Settings: settings, Choice: "1h"},
	} {
		if _, err := l.GrantRefused(context.Background(), rg, nil); !errors.Is(err, ledger.ErrNotFound) {
			t.Errorf("%+v: err = %v", rg, err)
		}
	}
	for _, rg := range []ledger.RefusedGrant{
		{Source: "workspace", Name: "a.example.com", Settings: settings, Choice: "once"},
		{Source: "workspace", Name: "a.example.com", Settings: settings, Choice: "1h", Options: ledger.OptionAnswer{Unit: "domain:com"}},
	} {
		if _, err := l.GrantRefused(context.Background(), rg, nil); !errors.Is(err, ledger.ErrBadChoice) {
			t.Errorf("%+v: err = %v", rg, err)
		}
	}
}

func TestAGrantFromTheListThatCannotBeRecordedIsNotTaken(t *testing.T) {
	l, _, _ := open(t)
	remember(t, l, "workspace", "a.example.com")
	_, err := l.GrantRefused(context.Background(), ledger.RefusedGrant{Source: "workspace", Name: "a.example.com", Settings: settings, Choice: "1h"},
		func(*ledger.Grant) error { return errors.New("disk full") })
	if err == nil {
		t.Fatal("no error")
	}
	if lookupDest(t, l, "workspace", "a.example.com") != nil || len(refused(t, l, "workspace")) != 1 {
		t.Error("taken")
	}
}

func TestTheDestinationGrantsInEffectAreCountedByHandlingAndAccess(t *testing.T) {
	l, _, _ := open(t)
	grant(t, l, "a.example.com", "1h", ledger.OptionAnswer{})
	grant(t, l, "b.example.com", "1h", ledger.OptionAnswer{})
	grant(t, l, "c.example.com", "1h", ledger.OptionAnswer{Handling: "passthrough"})
	got, err := l.CountDestinationGrants(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := map[ledger.GrantShape]int{{Handling: ledger.Inspect, Access: ledger.Read}: 2, {Handling: ledger.Passthrough}: 1}
	if len(got) != len(want) {
		t.Errorf("got %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%v: %d, want %d", k, got[k], v)
		}
	}
}

// A ledger of the first version is brought up to this one when opened: its
// grants stay in effect, as operation grants.
func TestALedgerOfTheFirstVersionIsBroughtUp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.db")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`
CREATE TABLE approvals (id TEXT PRIMARY KEY, state TEXT NOT NULL, source TEXT NOT NULL, fingerprint TEXT NOT NULL, created TEXT NOT NULL, expires TEXT NOT NULL, doc TEXT NOT NULL);
CREATE INDEX approvals_open ON approvals (state, source, fingerprint);
CREATE TABLE grants (id TEXT PRIMARY KEY, source TEXT NOT NULL, scope TEXT NOT NULL, destination TEXT NOT NULL, operation TEXT NOT NULL, target TEXT NOT NULL, method TEXT NOT NULL, path TEXT NOT NULL, fingerprint TEXT NOT NULL, op_key TEXT NOT NULL, expires TEXT, created TEXT NOT NULL, doc TEXT NOT NULL);
CREATE INDEX grants_match ON grants (source, destination, operation);
INSERT INTO grants VALUES ('gr-old', 'workspace', 'timed', 'api.example.com', '', '', 'POST', '/anything', '', '', NULL, '2026-11-01T00:00:00.000000000Z',
 '{"id":"gr-old","approval":"ap-old","source":"workspace","scope":"timed","created":"2026-11-01T00:00:00Z","summary":"POST /anything on api.example.com with no end","destination":"api.example.com","method":"POST","path":"/anything"}');
PRAGMA user_version = 1;`)
	if err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	l, err := ledger.Open(path, func() time.Time { return time.Date(2026, 11, 11, 9, 0, 0, 0, time.UTC) })
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	gs, err := l.Grants(context.Background())
	if err != nil || len(gs) != 1 || gs[0].Kind != ledger.GrantOperation {
		t.Fatalf("grants = %+v, %v", gs, err)
	}
	if g, err := l.Lookup(context.Background(), raw("/anything")); err != nil || g == nil || g.ID != "gr-old" {
		t.Errorf("lookup = %+v, %v", g, err)
	}
	if _, err := l.RememberRefused(context.Background(), "workspace", "a.example.com"); err != nil {
		t.Errorf("remember: %v", err)
	}
	if g := lookupDest(t, l, "workspace", "api.example.com"); g != nil {
		t.Errorf("an old grant is a destination grant: %+v", g)
	}
}
