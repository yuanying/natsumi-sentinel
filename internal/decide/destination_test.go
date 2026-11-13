package decide_test

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/yuanying/natsumi-sentinel/internal/audit"
	"github.com/yuanying/natsumi-sentinel/internal/decide"
	"github.com/yuanying/natsumi-sentinel/internal/ledger"
	"github.com/yuanying/natsumi-sentinel/internal/routes"
)

// destLedger answers destination grants from a map of names, and records
// what it was asked.
type destLedger struct {
	grants map[string]*ledger.Grant
	err    error
	asked  []string
}

func (d *destLedger) LookupDestination(_ context.Context, source, name string) (*ledger.Grant, error) {
	d.asked = append(d.asked, source+" "+name)
	if d.err != nil {
		return nil, d.err
	}
	g := d.grants[name]
	if g == nil || g.Source != source {
		return nil, nil
	}
	return g, nil
}

func inspectGrant(id string, access ledger.Access) *ledger.Grant {
	return &ledger.Grant{ID: id, Kind: ledger.GrantDestination, Source: "workspace", Unit: ledger.UnitName, Handling: ledger.Inspect, Access: access}
}

func passGrant(id string) *ledger.Grant {
	return &ledger.Grant{ID: id, Kind: ledger.GrantDestination, Source: "workspace", Unit: ledger.UnitName, Handling: ledger.Passthrough}
}

func grantsTable(dl *destLedger) decide.Table {
	return decide.Table{Destinations: &decide.DestinationGrants{
		Ledger: dl, Fixed: []string{"sentinel.example"}, SearchSuffixes: []string{"svc.cluster.local"},
	}}
}

func TestANameADestinationGrantCoversIsAnswered(t *testing.T) {
	dl := &destLedger{grants: map[string]*ledger.Grant{
		"docs.example.net": inspectGrant("gr-1", ledger.Read),
		"k8s.example.net":  passGrant("gr-2"),
	}}
	tbl := grantsTable(dl)
	for _, c := range []struct {
		name, grant string
		treatment   routes.Treatment
	}{
		{"docs.example.net", "gr-1", routes.Open},
		{"K8S.example.net.", "gr-2", "passthrough"},
	} {
		ans := tbl.DecideName(context.Background(), decide.NameQuery{Source: "workspace", Routes: pointsRoutes(t), Name: c.name})
		if ans.Verdict != audit.Allow || ans.Treatment != c.treatment || ans.Grant != c.grant || ans.Remember {
			t.Errorf("%s: %+v", c.name, ans)
		}
		if !strings.Contains(ans.Reason, "destination grant") || !strings.Contains(ans.Reason, c.grant) {
			t.Errorf("%s: reason %q", c.name, ans.Reason)
		}
	}
	if ans := tbl.DecideName(context.Background(), decide.NameQuery{Source: "other", Routes: pointsRoutes(t), Name: "docs.example.net"}); ans.Verdict != audit.Deny {
		t.Errorf("another source: %+v", ans)
	}
}

func TestANameNotInTheTableWithoutAGrantIsRefusedAndRemembered(t *testing.T) {
	tbl := grantsTable(&destLedger{})
	ans := tbl.DecideName(context.Background(), decide.NameQuery{Source: "workspace", Routes: pointsRoutes(t), Name: "unlisted.example.com"})
	if ans.Verdict != audit.Deny || ans.Reason != audit.ReasonDNSNotListed || !ans.Remember {
		t.Errorf("%+v", ans)
	}
}

func TestNamesThatCannotBeGrantedAreNotRemembered(t *testing.T) {
	dl := &destLedger{}
	tbl := grantsTable(dl)
	for _, name := range []string{"closed.example.com", "open.example.com.svc.cluster.local", "192.0.2.1", "com", "bad..name", "sentinel.example"} {
		ans := tbl.DecideName(context.Background(), decide.NameQuery{Source: "workspace", Routes: pointsRoutes(t), Name: name, SearchSuffixes: []string{"svc.cluster.local"}})
		if ans.Verdict != audit.Deny || ans.Remember {
			t.Errorf("%s: %+v", name, ans)
		}
	}
}

func TestWithoutDestinationGrantsNothingIsRememberedOrLookedUp(t *testing.T) {
	ans := decide.Table{}.DecideName(context.Background(), decide.NameQuery{Source: "workspace", Routes: pointsRoutes(t), Name: "unlisted.example.com"})
	if ans.Remember || ans.Verdict != audit.Deny {
		t.Errorf("%+v", ans)
	}
}

func TestATableNameIsDecidedByTheTableWhateverTheGrants(t *testing.T) {
	g := inspectGrant("gr-1", ledger.ReadWrite)
	dl := &destLedger{grants: map[string]*ledger.Grant{"closed.example.com": g, "other-port.example.com": g, "open.example.com.svc.cluster.local": g}}
	tbl := grantsTable(dl)
	rt := pointsRoutes(t)
	if ans := tbl.DecideName(context.Background(), decide.NameQuery{Source: "workspace", Routes: rt, Name: "closed.example.com"}); ans.Verdict != audit.Deny {
		t.Errorf("deny name: %+v", ans)
	}
	if ans := tbl.DecideName(context.Background(), decide.NameQuery{Source: "workspace", Routes: rt, Name: "open.example.com.svc.cluster.local"}); ans.Verdict != audit.Deny {
		t.Errorf("search suffix: %+v", ans)
	}
	ans := tbl.DecideConnection(context.Background(), decide.ConnectionQuery{Source: "workspace", Routes: rt, Address: netip.MustParseAddrPort("192.0.2.1:443"), Name: "other-port.example.com"})
	if ans.Verdict != audit.Deny || ans.Grant != nil {
		t.Errorf("another port of a table name: %+v", ans)
	}
	if len(dl.asked) != 0 {
		t.Errorf("the ledger was asked %v", dl.asked)
	}
}

func TestALedgerThatCannotBeReadAnswersNoName(t *testing.T) {
	tbl := grantsTable(&destLedger{err: errors.New("disk gone")})
	ans := tbl.DecideName(context.Background(), decide.NameQuery{Source: "workspace", Routes: pointsRoutes(t), Name: "docs.example.net"})
	if ans.Verdict != audit.Deny || ans.Error == "" || ans.Remember {
		t.Errorf("%+v", ans)
	}
	if !strings.HasPrefix(ans.Reason, "not an open destination in the routing table") {
		t.Errorf("reason %q", ans.Reason)
	}
	c := tbl.DecideConnection(context.Background(), decide.ConnectionQuery{Source: "workspace", Routes: pointsRoutes(t), Address: netip.MustParseAddrPort("192.0.2.1:443"), Name: "docs.example.net"})
	if c.Verdict != audit.Deny || c.Error == "" {
		t.Errorf("connection: %+v", c)
	}
}

func TestAConnectionADestinationGrantCoversIsOpenedOrPassedThroughOn443Only(t *testing.T) {
	dl := &destLedger{grants: map[string]*ledger.Grant{
		"docs.example.net": inspectGrant("gr-1", ledger.Read),
		"k8s.example.net":  passGrant("gr-2"),
	}}
	tbl := grantsTable(dl)
	rt := pointsRoutes(t)
	at := netip.MustParseAddrPort("198.51.100.7:443")
	open := tbl.DecideConnection(context.Background(), decide.ConnectionQuery{Source: "workspace", Routes: rt, Address: at, Name: "docs.example.net"})
	if open.Verdict != audit.Allow || open.Passthrough || open.Treatment != routes.Open || open.Grant == nil || open.Grant.ID != "gr-1" || open.Destination.Name != "docs.example.net" {
		t.Errorf("inspect: %+v", open)
	}
	pass := tbl.DecideConnection(context.Background(), decide.ConnectionQuery{Source: "workspace", Routes: rt, Address: at, Name: "k8s.example.net"})
	if pass.Verdict != audit.Allow || !pass.Passthrough || pass.Treatment != "passthrough" || pass.Grant == nil || pass.Grant.ID != "gr-2" {
		t.Errorf("passthrough: %+v", pass)
	}
	if !strings.Contains(pass.Reason, "reads and writes") {
		t.Errorf("passthrough reason %q", pass.Reason)
	}
	for _, port := range []uint16{80, 8443} {
		ans := tbl.DecideConnection(context.Background(), decide.ConnectionQuery{Source: "workspace", Routes: rt, Address: netip.AddrPortFrom(at.Addr(), port), Name: "docs.example.net"})
		if ans.Verdict != audit.Deny {
			t.Errorf("port %d: %+v", port, ans)
		}
	}
}

func grantedRequest(method string) decide.Request {
	return decide.Request{
		Source: "workspace", Granted: true, Port: 443, Method: method, Path: "/x", BodyComplete: true,
		Destination: routes.Destination{Name: "docs.example.net", Treatment: routes.Open},
		Settings:    routes.ApprovalSettings{Durations: nil},
	}
}

func TestOnAReadOnlyGrantReadsGoThroughAndWritesAreAsked(t *testing.T) {
	dl := &destLedger{grants: map[string]*ledger.Grant{"docs.example.net": inspectGrant("gr-1", ledger.Read)}}
	ops := &fakeLedger{}
	tbl := grantsTable(dl)
	tbl.Ledger = ops
	for _, m := range []string{"GET", "HEAD", "OPTIONS", "TRACE"} {
		req := grantedRequest(m)
		req.Routes = pointsRoutes(t)
		if d := tbl.Decide(context.Background(), req); d.Verdict != audit.Allow || d.Grant != "gr-1" {
			t.Errorf("%s: %+v", m, d)
		}
	}
	req := grantedRequest("POST")
	req.Routes = pointsRoutes(t)
	d := tbl.Decide(context.Background(), req)
	if d.Verdict != audit.Ask || d.Approval != "ap-1" {
		t.Fatalf("POST: %+v", d)
	}
	if len(ops.held) != 1 || ops.held[0].Destination != "docs.example.net" || ops.held[0].Operation != "" || ops.held[0].Method != "POST" {
		t.Errorf("held %+v", ops.held)
	}
	ops.grant = &ledger.Grant{ID: "gr-op"}
	if d := tbl.Decide(context.Background(), req); d.Verdict != audit.Allow || d.Grant != "gr-op" {
		t.Errorf("POST with an operation grant: %+v", d)
	}
}

func TestOnAReadWriteGrantWritesGoThrough(t *testing.T) {
	dl := &destLedger{grants: map[string]*ledger.Grant{"docs.example.net": inspectGrant("gr-1", ledger.ReadWrite)}}
	ops := &fakeLedger{}
	tbl := grantsTable(dl)
	tbl.Ledger = ops
	req := grantedRequest("DELETE")
	req.Routes = pointsRoutes(t)
	if d := tbl.Decide(context.Background(), req); d.Verdict != audit.Allow || d.Grant != "gr-1" {
		t.Errorf("%+v", d)
	}
	if len(ops.held)+len(ops.looked) != 0 {
		t.Error("the operation grants were asked")
	}
}

func TestARequestAfterItsDestinationGrantEndedIsRefused(t *testing.T) {
	dl := &destLedger{grants: map[string]*ledger.Grant{}}
	tbl := grantsTable(dl)
	req := grantedRequest("GET")
	req.Routes = pointsRoutes(t)
	if d := tbl.Decide(context.Background(), req); d.Verdict != audit.Deny || !d.Fixed {
		t.Errorf("%+v", d)
	}
	// What is left is a passthrough grant: it does not open a connection.
	dl.grants["docs.example.net"] = passGrant("gr-2")
	if d := tbl.Decide(context.Background(), req); d.Verdict != audit.Deny {
		t.Errorf("passthrough left: %+v", d)
	}
	dl.err = errors.New("disk gone")
	if d := tbl.Decide(context.Background(), req); d.Verdict != audit.Deny || d.Error == "" {
		t.Errorf("ledger gone: %+v", d)
	}
}

func TestGrantableNames(t *testing.T) {
	rt := pointsRoutes(t)
	fixed, sfx := []string{"sentinel.example"}, []string{"svc.cluster.local"}
	for _, name := range []string{"docs.example.net", "a.b.c.example", "api.ns.svc.cluster.local", "unlisted.example.com.svc.cluster.local"} {
		if err := decide.Grantable(rt, name, fixed, sfx); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for _, name := range []string{"open.example.com", "other-port.example.com", "192.0.2.1", "2001:db8::1", "sentinel.example", "open.example.com.svc.cluster.local", "com", "github.io", "bad name", strings.Repeat("a", 64) + ".example.com"} {
		if err := decide.Grantable(rt, name, fixed, sfx); err == nil {
			t.Errorf("%s is grantable", name)
		}
	}
	if err := decide.Grantable(rt, "closed.example.com", fixed, sfx); !errors.Is(err, decide.ErrTableDenies) {
		t.Errorf("closed: %v", err)
	}
}
