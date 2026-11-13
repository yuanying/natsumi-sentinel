package decide

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"

	"github.com/yuanying/natsumi-sentinel/internal/audit"
	"github.com/yuanying/natsumi-sentinel/internal/domains"
	"github.com/yuanying/natsumi-sentinel/internal/ledger"
	"github.com/yuanying/natsumi-sentinel/internal/routes"
	"github.com/yuanying/natsumi-sentinel/internal/upstream"
)

// This file is step 3 for the names not in the routing table: the ledger's
// destination grants (docs/adr/0008, docs/destination-grants.md "照合の
// 決まり").

// DestinationLedger is the part of the ledger the destination grants use.
type DestinationLedger interface {
	LookupDestination(ctx context.Context, source, name string) (*ledger.Grant, error)
}

// DestinationGrants turn the destination grants on.
type DestinationGrants struct {
	Ledger DestinationLedger
	// Fixed are the gate's own names, and SearchSuffixes those of the
	// workspace's resolver: neither is granted.
	Fixed          []string
	SearchSuffixes []string
	// Inside are the inside domains: what is decided for a name under one
	// says so in its reason (docs/adr/0008 "記録と知らせ").
	Inside upstream.Domains
}

// MarkInside is put at the end of the reason of what a destination grant
// decides for an inside name.
const MarkInside = "; an inside name"

// insideMark is MarkInside for an inside name, and empty for any other.
func (t Table) insideMark(name string) string {
	if t.Destinations != nil && t.Destinations.Inside.Inside(name) {
		return MarkInside
	}
	return ""
}

// GrantPort is the only port a destination grant covers (docs/adr/0008
// "ポートは 443 だけ").
const GrantPort = upstream.Port

// ErrTableDenies is a name the routing table denies: no approval lets it
// through.
var ErrTableDenies = errors.New("the routing table denies the name; to change it, the owner edits the table")

// Grantable says why a destination grant may not be given for name, or
// nil when it may (docs/destination-grants.md "許されない名前"). name is
// compared as the routing table compares names.
func Grantable(table *routes.Table, name string, fixed, suffixes []string) error {
	name = routes.Normalize(name)
	if _, err := netip.ParseAddr(name); err == nil {
		return errors.New("an IP address: a destination grant is for a name")
	}
	if err := upstream.CheckName(name); err != nil {
		return fmt.Errorf("not a name: %w", err)
	}
	for _, f := range fixed {
		if routes.Normalize(f) == name {
			return errors.New("the gate's own name")
		}
	}
	switch {
	case table.Listed(name) && !table.Resolvable(name):
		return ErrTableDenies
	case table.Listed(name):
		return errors.New("the routing table has the name; the table decides it")
	case searched(table, name, suffixes):
		return errors.New("a name in the routing table with a search suffix added: the workspace's resolver tries it on the way to the name")
	case domains.IsPublicSuffix(name):
		return errors.New("a public suffix, under which anyone can make names")
	}
	return nil
}

// destinationGrant finds the grant that covers name for source, when the
// grants are on and name could have one.
func (t Table) destinationGrant(ctx context.Context, table *routes.Table, source, name string) (*ledger.Grant, error) {
	dg := t.Destinations
	if dg == nil || dg.Ledger == nil || Grantable(table, name, dg.Fixed, dg.SearchSuffixes) != nil {
		return nil, nil
	}
	return dg.Ledger.LookupDestination(ctx, source, name)
}

// rememberable reports whether a name refused for not being in the table
// is kept on the list of refused names: only one a grant could be given
// for.
func (t Table) rememberable(table *routes.Table, name string) bool {
	dg := t.Destinations
	return dg != nil && dg.Ledger != nil && Grantable(table, name, dg.Fixed, dg.SearchSuffixes) == nil
}

// The reasons of what a destination grant decides.
const (
	reasonNoLedger = "the ledger could not be read, so no destination grant covers the name"
)

func grantTreatment(g *ledger.Grant) routes.Treatment {
	if g.Handling == ledger.Passthrough {
		return "passthrough"
	}
	return routes.Open
}

// GrantedDestination is the open destination a destination grant makes of
// a name: no rules, on port 443. What it lets through is decided by the
// grant, request by request.
func GrantedDestination(name string) routes.Destination {
	return routes.Destination{Name: name, Treatment: routes.Open, Ports: []uint16{GrantPort}}
}

// decideGranted decides on a request on a connection a destination grant
// opened. The grant is looked up again for each request: one that ended
// lets no more requests through (docs/destination-grants.md "接続と要求").
func (t Table) decideGranted(ctx context.Context, req Request) Decision {
	name := req.Destination.Name
	if t.Destinations == nil || req.Routes == nil {
		return Decision{Verdict: audit.Deny, Reason: "the connection was opened by a destination grant, and the gate has none", Error: "no destination grants"}
	}
	if req.Routes.Listed(name) {
		return Decision{Verdict: audit.Deny, Fixed: true, Reason: "the routing table has the name now; open a new connection, to be decided by the table"}
	}
	g, err := t.destinationGrant(ctx, req.Routes, req.Source, name)
	if err != nil {
		return Decision{Verdict: audit.Deny, Reason: "the ledger could not be read, so no destination grant covers the request", Error: err.Error()}
	}
	if g == nil || g.Handling != ledger.Inspect {
		return Decision{Verdict: audit.Deny, Fixed: true, Reason: "no destination grant opens the name any more; the grant the connection was opened by has ended"}
	}
	if g.Access == ledger.ReadWrite {
		return Decision{Verdict: audit.Allow, Grant: g.ID, Reason: fmt.Sprintf("the destination grant %s opens the name for reads and writes", g.ID) + t.insideMark(name)}
	}
	if !isWrite(req.Method) {
		return Decision{Verdict: audit.Allow, Grant: g.ID, Reason: fmt.Sprintf("a read: the destination grant %s opens the name for reads", g.ID) + t.insideMark(name)}
	}
	// A write is a raw operation on a destination that asks
	// (docs/adr/0008 "読みだけか、読み書きか").
	d := GrantedDestination(name)
	d.Default = routes.Ask
	req.Destination = d
	dec := t.decide(ctx, req, []Operation{{}})
	dec.Reason = fmt.Sprintf("a write, and the destination grant %s opens the name for reads only: %s", g.ID, dec.Reason) + t.insideMark(name)
	return dec
}

func isWrite(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return false
	}
	return true
}
