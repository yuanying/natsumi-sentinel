package decide_test

import (
	"context"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/yuanying/natsumi-sentinel/internal/audit"
	"github.com/yuanying/natsumi-sentinel/internal/decide"
	"github.com/yuanying/natsumi-sentinel/internal/ledger"
	"github.com/yuanying/natsumi-sentinel/internal/routes"
)

const pointsTable = `
destinations:
  - name: open.example.com
    treatment: open
    default: allow
  - name: closed.example.com
    treatment: deny
  - name: other-port.example.com
    treatment: open
    default: allow
    ports: [8443]
passthrough:
  - cidr: 192.0.2.0/24
    ports: [6443]
`

func pointsRoutes(t *testing.T) *routes.Table {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "r.yaml"), []byte(pointsTable), 0o600); err != nil {
		t.Fatal(err)
	}
	tbl, err := routes.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	return tbl
}

// recordingJudge keeps what it was shown and lets everything through.
type recordingJudge struct {
	asked []decide.Question
	allow bool
}

func (j *recordingJudge) Judge(_ context.Context, q decide.Question) decide.Judgement {
	j.asked = append(j.asked, q)
	return decide.Judgement{Allow: j.allow, Reason: "the judge lets it through"}
}

func TestAnOpenNameIsAnsweredAndAnyOtherRefused(t *testing.T) {
	tbl := pointsRoutes(t)
	cases := []struct {
		name, want  string
		verdict     audit.Verdict
		treatment   routes.Treatment
		searchAdded bool
	}{
		{name: "open.example.com", verdict: audit.Allow, treatment: routes.Open, want: "an open destination in the routing table"},
		{name: "closed.example.com", verdict: audit.Deny, treatment: routes.Closed, want: audit.ReasonDNSDenied},
		{name: "unlisted.example.com", verdict: audit.Deny, treatment: routes.Closed, want: audit.ReasonDNSNotListed},
		{name: "open.example.com.svc.cluster.local", verdict: audit.Deny, treatment: routes.Closed, want: audit.ReasonDNSSearchSuffix},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := decide.Table{}.DecideName(context.Background(), decide.NameQuery{
				Source: "workspace", Routes: tbl, Name: c.name, SearchSuffixes: []string{".svc.cluster.local."},
			})
			if got.Verdict != c.verdict || got.Treatment != c.treatment || got.Reason != c.want {
				t.Errorf("DecideName(%s) = %+v, want %s %s %q", c.name, got, c.verdict, c.treatment, c.want)
			}
		})
	}
}

func TestAConnectionToAPassedThroughRangeGoesStraightThrough(t *testing.T) {
	tbl := pointsRoutes(t)
	got := decide.Table{}.DecideConnection(context.Background(), decide.ConnectionQuery{
		Source: "workspace", Routes: tbl, Address: netip.MustParseAddrPort("192.0.2.10:6443"),
	})
	if got.Verdict != audit.Allow || !got.Passthrough || got.Reason != "the address range and port are passed through" {
		t.Errorf("DecideConnection = %+v", got)
	}
}

func TestAConnectionOutsideTheRangesWaitsForItsName(t *testing.T) {
	tbl := pointsRoutes(t)
	got := decide.Table{}.DecideConnection(context.Background(), decide.ConnectionQuery{
		Source: "workspace", Routes: tbl, Address: netip.MustParseAddrPort("[::ffff:198.51.100.1]:443"),
	})
	if !got.NeedName || got.Verdict != "" || got.Passthrough {
		t.Errorf("DecideConnection = %+v, want it to wait for the name", got)
	}
}

func TestAConnectionIsOpenedOnlyForAnOpenNameOnItsPort(t *testing.T) {
	tbl := pointsRoutes(t)
	cases := []struct {
		name      string
		port      uint16
		verdict   audit.Verdict
		treatment routes.Treatment
		reason    string
	}{
		{name: "open.example.com", port: 443, verdict: audit.Allow, treatment: routes.Open, reason: "an open destination in the routing table"},
		{name: "closed.example.com", port: 443, verdict: audit.Deny, treatment: routes.Closed, reason: "the routing table denies this destination"},
		{name: "other-port.example.com", port: 443, verdict: audit.Deny, treatment: routes.Closed, reason: "not in the routing table on this port"},
		{name: "unlisted.example.com", port: 443, verdict: audit.Deny, treatment: routes.Closed, reason: "not in the routing table on this port"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := decide.Table{}.DecideConnection(context.Background(), decide.ConnectionQuery{
				Source: "workspace", Routes: tbl, Name: c.name,
				Address: netip.AddrPortFrom(netip.MustParseAddr("198.51.100.1"), c.port),
			})
			if got.Verdict != c.verdict || got.Treatment != c.treatment || got.Reason != c.reason || got.NeedName {
				t.Errorf("DecideConnection(%s:%d) = %+v", c.name, c.port, got)
			}
			if c.verdict == audit.Allow && got.Destination.Name != c.name {
				t.Errorf("Destination = %+v, want %s", got.Destination, c.name)
			}
		})
	}
}

func TestTheJudgeMayLetThroughOnlyWhatIsLeftOver(t *testing.T) {
	tbl := pointsRoutes(t)
	j := &recordingJudge{allow: true}
	tb := decide.Table{Judge: j}
	ctx := context.Background()

	if got := tb.DecideName(ctx, decide.NameQuery{Source: "workspace", Routes: tbl, Name: "closed.example.com"}); got.Verdict != audit.Deny {
		t.Errorf("a name the table denies = %+v, want it denied whatever the judge says", got)
	}
	if got := tb.DecideName(ctx, decide.NameQuery{Source: "workspace", Routes: tbl, Name: "open.example.com"}); got.Verdict != audit.Allow {
		t.Errorf("an open name = %+v", got)
	}
	if len(j.asked) != 0 {
		t.Fatalf("the judge was asked about %+v, which the table decides", j.asked)
	}
	got := tb.DecideName(ctx, decide.NameQuery{Source: "workspace", Routes: tbl, Name: "unlisted.example.com"})
	if got.Verdict != audit.Allow || got.Reason != "the judge lets it through" {
		t.Errorf("an unlisted name with a judge that allows = %+v", got)
	}
	if len(j.asked) != 1 || j.asked[0].Point != decide.PointName || j.asked[0].Name != "unlisted.example.com" || j.asked[0].Source != "workspace" {
		t.Errorf("the judge was shown %+v", j.asked)
	}
}

func TestWithoutAJudgeAnAskedRequestIsHeldAsBefore(t *testing.T) {
	d, s := dest(t, "api.example.com")
	l := &fakeLedger{}
	got := decide.Table{Ledger: l}.Decide(context.Background(), decide.Request{
		Source: "workspace", Destination: d, Settings: s, Port: 443, Method: http.MethodPost, Path: "/anything",
	})
	if got.Verdict != audit.Ask || len(l.held) != 1 {
		t.Errorf("Decide = %+v, held %d", got, len(l.held))
	}
}

func TestTheJudgeIsAskedAboutARequestOnlyAfterTheLedgerHasNoGrant(t *testing.T) {
	d, s := dest(t, "api.example.com")
	req := decide.Request{Source: "workspace", Destination: d, Settings: s, Port: 443, Method: http.MethodPost, Path: "/anything"}

	j := &recordingJudge{allow: true}
	granted := &fakeLedger{grant: &ledger.Grant{ID: "g1"}}
	if got := (decide.Table{Ledger: granted, Judge: j}).Decide(context.Background(), req); got.Verdict != audit.Allow || got.Grant != "g1" {
		t.Errorf("a granted request = %+v", got)
	}
	denied := req
	denied.Method, denied.Path = http.MethodDelete, "/repos/o/r"
	if got := (decide.Table{Ledger: &fakeLedger{}, Judge: j}).Decide(context.Background(), denied); got.Verdict != audit.Deny {
		t.Errorf("a request the table denies = %+v", got)
	}
	if len(j.asked) != 0 {
		t.Fatalf("the judge was asked about %+v", j.asked)
	}

	l := &fakeLedger{}
	got := decide.Table{Ledger: l, Judge: j}.Decide(context.Background(), req)
	if got.Verdict != audit.Allow || got.Reason != "the judge lets it through" || len(l.held) != 0 {
		t.Errorf("Decide = %+v, held %d", got, len(l.held))
	}
	if len(j.asked) != 1 || j.asked[0].Point != decide.PointRequest || j.asked[0].Request == nil || j.asked[0].Name != "api.example.com" || j.asked[0].Port != 443 {
		t.Errorf("the judge was shown %+v", j.asked)
	}
}

func TestAJudgeThatDoesNotAllowLeavesTheRequestHeld(t *testing.T) {
	d, s := dest(t, "api.example.com")
	l := &fakeLedger{}
	got := decide.Table{Ledger: l, Judge: &recordingJudge{}}.Decide(context.Background(), decide.Request{
		Source: "workspace", Destination: d, Settings: s, Port: 443, Method: http.MethodPost, Path: "/anything",
	})
	if got.Verdict != audit.Ask || len(l.held) != 1 {
		t.Errorf("Decide = %+v, held %d", got, len(l.held))
	}
}
