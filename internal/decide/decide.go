// Package decide is where the gate decides whether a request read on an
// open destination goes out (docs/adr/0004).
//
// The request is first matched to an operation: by the destination's
// connector, when it has one, or else by the destination's rules. A
// request neither names is a raw operation. The table then says allow, ask
// or deny for the operation; ask looks for a grant in the ledger and,
// finding none, holds the request for the owner.
package decide

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/yuanying/natsumi-sentinel/internal/audit"
	"github.com/yuanying/natsumi-sentinel/internal/ledger"
	"github.com/yuanying/natsumi-sentinel/internal/routes"
)

// Request is what the gate knows about a request when it decides.
type Request struct {
	// Source is the listener the connection came in on.
	Source string
	// Destination is the open destination, as the routing table has it.
	Destination routes.Destination
	// Settings are the table's approval settings.
	Settings routes.ApprovalSettings
	Port     uint16
	Method   string
	Path     string
	Query    string
	Header   http.Header
	// Body is the start of the request body, up to the audit body limit.
	// BodyComplete is false when the body goes on past it.
	Body         []byte
	BodyComplete bool
	// BodySummary is what the audit record keeps of Body.
	BodySummary *audit.Body
}

// Operation is a request matched to a name.
type Operation struct {
	// Name is empty for a raw operation.
	Name string
	// Params are what the request names: the path's parameters, and
	// whatever a connector reads.
	Params []routes.Param
	// Target names the params that make the target.
	Target []string
	// Facts are what a connector looked up upstream about the target. They
	// are shown on an approval and not matched.
	Facts []routes.Param
	// Fingerprint, when set, is what a grant of one request is matched by
	// for this operation, in place of the request's: one operation of
	// several in one request (a ref of a push) has its own.
	Fingerprint string
}

// Result is what a connector made of a request. A zero Result leaves the
// request to the rules.
type Result struct {
	// Read is a request that only reads: it goes through without the
	// table (docs/adr/0005).
	Read bool
	// Refusal, when set, refuses the request for this reason, whatever
	// the table says: the connector could not read it as an operation of
	// a shape it takes.
	Refusal string
	// Operations are what the request does. Several go out together or
	// not at all.
	Operations []Operation
	// Request, when set, is what the record keeps of the body in place
	// of the body (a push keeps its commands only).
	Request *audit.Body
}

// Connector reads requests to the destinations it is for, which the rules
// cannot match to operations by method, path and body alone
// (docs/adr/0005). An error refuses the request: the connector could not
// find out what it is (an upstream it asked did not answer).
type Connector interface {
	Read(ctx context.Context, req Request) (Result, error)
}

// Ledger is the part of the ledger a decision uses.
type Ledger interface {
	LookupAll(ctx context.Context, fs []ledger.Facts) ([]*ledger.Grant, error)
	HoldAll(ctx context.Context, fs []ledger.Facts, s routes.ApprovalSettings) (*ledger.Approval, bool, error)
}

// Decision is the answer and what it was made of.
type Decision struct {
	Verdict audit.Verdict
	Reason  string
	// Operation and Target are the operation's name and target; empty for
	// a raw operation. A request of several operations has their names
	// joined by ", " and their targets by "; ".
	Operation string
	Target    string
	// Approval is the approval an asked request is held on, and
	// ApprovalCreated whether this request made it.
	Approval        string
	ApprovalCreated bool
	// Grant is the grant an asked request went through on; the grants,
	// joined by ",", for a request of several operations.
	Grant string
	// Fixed is a refusal that is not the table's (a connector's): no change
	// to the table lets it through.
	Fixed bool
	// Request, when set, is what the record keeps of the body.
	Request *audit.Body
	// Error is set when the decision could not be made as the table says
	// (the ledger or a connector failed): the request is refused.
	Error string
}

// Decider decides on a request.
type Decider interface {
	Decide(ctx context.Context, req Request) Decision
}

// Table decides by the routing table and the ledger.
type Table struct {
	// Ledger holds the grants and approvals. Without one, nothing the
	// table asks about goes through.
	Ledger Ledger
	// GitHub reads the requests to destinations with a GitHub section.
	// Without one, those requests are refused: the table says how they
	// are named, and nothing here can read them.
	GitHub Connector
}

// Decide implements Decider.
func (t Table) Decide(ctx context.Context, req Request) Decision {
	d := req.Destination
	var res Result
	if d.GitHub != nil {
		if t.GitHub == nil {
			return Decision{Verdict: audit.Deny, Reason: "the destination is read by the GitHub connector, and the gate has none", Error: "no GitHub connector"}
		}
		var err error
		res, err = t.GitHub.Read(ctx, req)
		if err != nil {
			return Decision{Verdict: audit.Deny, Reason: "the request could not be matched to an operation", Error: err.Error()}
		}
	}
	switch {
	case res.Refusal != "":
		return Decision{Verdict: audit.Deny, Reason: "refused: " + res.Refusal, Fixed: true, Request: res.Request}
	case res.Read:
		return Decision{Verdict: audit.Allow, Reason: "a read: the connector lets reads through", Request: res.Request}
	}
	ops := res.Operations
	if len(ops) == 0 {
		op := Operation{}
		if m, ok := d.MatchRequest(req.Method, req.Path, routes.ParseBody(req.Body, req.BodyComplete)); ok {
			op = Operation{Name: m.Operation, Params: m.Params, Target: m.Target}
		}
		ops = []Operation{op}
	}
	dec := t.decide(ctx, req, ops)
	dec.Request = res.Request
	var names, targets []string
	for _, op := range ops {
		names = append(names, op.Name)
		targets = append(targets, ledger.TargetText(op.Params, op.Target))
	}
	dec.Operation = joinSome(names, ", ")
	dec.Target = joinSome(targets, "; ")
	return dec
}

// joinSome joins the parts unless they are all empty.
func joinSome(parts []string, sep string) string {
	for _, p := range parts {
		if p != "" {
			return strings.Join(parts, sep)
		}
	}
	return ""
}

// what an operation is called in a reason, and where its action comes
// from.
func describe(d routes.Destination, op Operation) (what, from string) {
	what = "the operation " + op.Name
	if op.Name == "" {
		what = "a request no rule names"
	}
	from = "the table"
	if _, ok := d.Operations[op.Name]; !ok || op.Name == "" {
		from = "the destination's default"
	}
	return what, from
}

func (t Table) decide(ctx context.Context, req Request, ops []Operation) Decision {
	d := req.Destination
	var (
		asked   []Operation
		allowed []string
	)
	for _, op := range ops {
		what, from := describe(d, op)
		switch d.ActionFor(op.Name) {
		case routes.Allow:
			allowed = append(allowed, fmt.Sprintf("%s: %s allows it", what, from))
		case routes.Ask:
			asked = append(asked, op)
		default:
			return Decision{Verdict: audit.Deny, Reason: fmt.Sprintf("%s: %s denies it", what, from)}
		}
	}
	if len(asked) == 0 {
		return Decision{Verdict: audit.Allow, Reason: strings.Join(allowed, "; ")}
	}

	what, from := describe(d, asked[0])
	if len(asked) > 1 {
		what, from = fmt.Sprintf("%d operations", len(asked)), "the table or the destination's default"
	}
	if t.Ledger == nil {
		return Decision{Verdict: audit.Deny, Reason: fmt.Sprintf("%s: %s asks about it, and there is no ledger", what, from), Error: "no ledger"}
	}
	facts := make([]ledger.Facts, len(asked))
	for i, op := range asked {
		f := ledger.Facts{
			Source:      req.Source,
			Destination: d.Name,
			Method:      req.Method,
			Path:        req.Path,
			Query:       req.Query,
			Operation:   op.Name,
			Params:      op.Params,
			Target:      op.Target,
			Facts:       op.Facts,
			Body:        req.BodySummary,
			Fingerprint: fingerprint(req),
			Exact:       req.BodyComplete,
		}
		if op.Fingerprint != "" {
			f.Fingerprint, f.Exact = op.Fingerprint, true
		}
		facts[i] = f
	}
	grants, err := t.Ledger.LookupAll(ctx, facts)
	if err != nil {
		return Decision{Verdict: audit.Deny, Reason: fmt.Sprintf("%s: %s asks about it, and the ledger could not be read, so there is no grant", what, from), Error: err.Error()}
	}
	var (
		ids     []string
		without []ledger.Facts
	)
	for i, g := range grants {
		if g == nil {
			without = append(without, facts[i])
			continue
		}
		ids = append(ids, g.ID)
	}
	if len(without) == 0 {
		return Decision{Verdict: audit.Allow, Grant: strings.Join(ids, ","), Reason: fmt.Sprintf("%s: %s asks about it, and the grant %s covers it", what, from, strings.Join(ids, ", "))}
	}
	a, created, err := t.Ledger.HoldAll(ctx, without, req.Settings)
	if err != nil {
		return Decision{Verdict: audit.Deny, Reason: fmt.Sprintf("%s: %s asks about it, and the ledger could not hold it for the owner", what, from), Error: err.Error()}
	}
	return Decision{
		Verdict:         audit.Ask,
		Approval:        a.ID,
		ApprovalCreated: created,
		Reason:          fmt.Sprintf("%s: %s asks about it; held for the owner as %s", what, from, a.ID),
	}
}

// fingerprint covers what makes a request the same request again: where
// it goes, what it does, and its body as far as the gate read it.
func fingerprint(req Request) string {
	h := sha256.New()
	for _, s := range []string{req.Source, req.Destination.Name, strconv.Itoa(int(req.Port)), req.Method, req.Path, req.Query, strconv.FormatBool(req.BodyComplete)} {
		_, _ = fmt.Fprintf(h, "%d:%s", len(s), s)
	}
	_, _ = fmt.Fprintf(h, "%d:", len(req.Body))
	h.Write(req.Body)
	return hex.EncodeToString(h.Sum(nil))
}
