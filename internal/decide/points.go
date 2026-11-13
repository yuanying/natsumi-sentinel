package decide

import (
	"context"
	"net/netip"
	"strings"

	"github.com/yuanying/natsumi-sentinel/internal/audit"
	"github.com/yuanying/natsumi-sentinel/internal/routes"
)

// The gate asks the same Table at each of three points: a name resolution
// query, a connection (before and at its TLS handshake), and a request read
// on an open connection (docs/adr/0008, docs/destination-grants.md "判定の
// 場所"). At every point the steps go in one order:
//
//  1. what the routing table and the operation table deny;
//  2. what they allow, by their rules;
//  3. the ledger's grants;
//  4. the judge, when there is one;
//  5. what is left: an operation is asked about, and anything else is
//     refused.
//
// A step decides or leaves the question to the next one. The judge cannot
// undo a refusal of step 1 or a grant of step 3: it is only shown what
// would be asked about or refused at step 5.

// Point is where the gate asks.
type Point string

const (
	PointName       Point = "name"
	PointConnection Point = "connection"
	PointRequest    Point = "request"
)

// Question is what the judge is shown, the same at every point.
type Question struct {
	Point  Point
	Source string
	Name   string
	// Port is the connection's; zero for a name.
	Port uint16
	// Request is the request asked about, at PointRequest.
	Request *Request
}

// Judgement is the judge's answer. A Judgement that does not allow leaves
// the question to step 5.
type Judgement struct {
	Allow  bool
	Reason string
}

// Judge is step 4. What it is shown and how it is put in are for the
// version that brings one (docs/adr/0008); Table.Judge is nil until then.
type Judge interface {
	Judge(ctx context.Context, q Question) Judgement
}

// judge asks t's judge, if it has one.
func (t Table) judge(ctx context.Context, q Question) (Judgement, bool) {
	if t.Judge == nil {
		return Judgement{}, false
	}
	j := t.Judge.Judge(ctx, q)
	return j, j.Allow
}

// NameQuery is a name resolution query to decide on.
type NameQuery struct {
	Source string
	Routes *routes.Table
	Name   string
	// SearchSuffixes are the search list of the source's resolver. A
	// refused name that is a listed name with one of them added is told
	// by its own reason.
	SearchSuffixes []string
}

// NameAnswer is what a name is answered with.
type NameAnswer struct {
	// Verdict is Allow when the name is answered with its real
	// addresses, and Deny when it gets NXDOMAIN.
	Verdict   audit.Verdict
	Treatment routes.Treatment
	Reason    string
}

// NameDecider decides on name resolution queries.
type NameDecider interface {
	DecideName(ctx context.Context, q NameQuery) NameAnswer
}

// DecideName implements NameDecider.
func (t Table) DecideName(ctx context.Context, q NameQuery) NameAnswer {
	name := routes.Normalize(q.Name)
	// 1. A name the table lists, but not as open.
	if q.Routes.Listed(name) && !q.Routes.Resolvable(name) {
		return NameAnswer{Verdict: audit.Deny, Treatment: routes.Closed, Reason: audit.ReasonDNSDenied}
	}
	// 2. An open name.
	if q.Routes.Resolvable(name) {
		return NameAnswer{Verdict: audit.Allow, Treatment: routes.Open, Reason: "an open destination in the routing table"}
	}
	// 3. The ledger's destination grants go here (docs/destination-grants.md).
	// 4.
	if j, ok := t.judge(ctx, Question{Point: PointName, Source: q.Source, Name: name}); ok {
		return NameAnswer{Verdict: audit.Allow, Treatment: routes.Open, Reason: j.Reason}
	}
	// 5.
	reason := audit.ReasonDNSNotListed
	if searched(q.Routes, name, q.SearchSuffixes) {
		reason = audit.ReasonDNSSearchSuffix
	}
	return NameAnswer{Verdict: audit.Deny, Treatment: routes.Closed, Reason: reason}
}

// searched reports whether name is a name in table with one of the search
// suffixes added.
func searched(table *routes.Table, name string, suffixes []string) bool {
	for _, sfx := range suffixes {
		sfx = strings.TrimPrefix(routes.Normalize(sfx), ".")
		if sfx == "" {
			continue
		}
		if base, ok := strings.CutSuffix(name, "."+sfx); ok && base != "" && table.Listed(base) {
			return true
		}
	}
	return false
}

// ConnectionQuery is a connection to decide on. It is asked twice: first
// with the original destination only, as the connection comes in, and then,
// unless that decided, with the name its TLS handshake asks for.
type ConnectionQuery struct {
	Source  string
	Routes  *routes.Table
	Address netip.AddrPort
	// Name is the SNI; empty before the handshake.
	Name string
}

// ConnectionAnswer is what is done with a connection.
type ConnectionAnswer struct {
	// NeedName is set, with no Verdict, when the connection is not
	// decided before its name is known.
	NeedName bool
	Verdict  audit.Verdict
	// Passthrough is set when the connection goes straight through,
	// without its TLS being terminated.
	Passthrough bool
	// Treatment is the destination's, for an opened connection or one
	// the table names; Closed for a name it does not have on the port.
	Treatment routes.Treatment
	// Destination is the open destination, when the connection is opened.
	Destination routes.Destination
	Reason      string
}

// ConnectionDecider decides on connections.
type ConnectionDecider interface {
	DecideConnection(ctx context.Context, q ConnectionQuery) ConnectionAnswer
}

// DecideConnection implements ConnectionDecider.
func (t Table) DecideConnection(ctx context.Context, q ConnectionQuery) ConnectionAnswer {
	if q.Name == "" {
		// 2. The table's passthrough is by the address range and port,
		// and needs no name.
		if q.Routes.Passthrough(q.Address) {
			return ConnectionAnswer{Verdict: audit.Allow, Passthrough: true, Reason: "the address range and port are passed through"}
		}
		return ConnectionAnswer{NeedName: true}
	}
	name := routes.Normalize(q.Name)
	d, listed := q.Routes.Lookup(name, q.Address.Port())
	// 1. A name the table has on the port, but not as open.
	if listed && d.Treatment != routes.Open {
		return ConnectionAnswer{Verdict: audit.Deny, Treatment: d.Treatment, Reason: "the routing table denies this destination"}
	}
	// 2.
	if listed {
		return ConnectionAnswer{Verdict: audit.Allow, Treatment: routes.Open, Destination: d, Reason: "an open destination in the routing table"}
	}
	// 3. The ledger's destination grants go here (docs/destination-grants.md).
	// 4. A judge cannot open a connection yet: an opened connection is
	// for a destination of the table, whose requests are decided by its
	// rules.
	// 5.
	return ConnectionAnswer{Verdict: audit.Deny, Treatment: routes.Closed, Reason: "not in the routing table on this port"}
}
