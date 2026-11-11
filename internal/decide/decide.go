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
	Name string
	// Params are what the request names: the path's parameters, and
	// whatever a connector reads.
	Params []routes.Param
	// Target names the params that make the target.
	Target []string
}

// Connector reads requests to one destination that the rules cannot match
// to operations by method and path alone (docs/adr/0005). ok is false
// when it leaves the request to the rules. An error refuses the request.
type Connector interface {
	Operation(ctx context.Context, req Request) (op Operation, ok bool, err error)
}

// Ledger is the part of the ledger a decision uses.
type Ledger interface {
	Lookup(ctx context.Context, f ledger.Facts) (*ledger.Grant, error)
	Hold(ctx context.Context, f ledger.Facts, s routes.ApprovalSettings) (*ledger.Approval, bool, error)
}

// Decision is the answer and what it was made of.
type Decision struct {
	Verdict audit.Verdict
	Reason  string
	// Operation and Target are the operation's name and target; empty for
	// a raw operation.
	Operation string
	Target    string
	// Approval is the approval an asked request is held on, and
	// ApprovalCreated whether this request made it.
	Approval        string
	ApprovalCreated bool
	// Grant is the grant an asked request went through on.
	Grant string
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
	// Connectors are keyed by the destination's name.
	Connectors map[string]Connector
}

// Decide implements Decider.
func (t Table) Decide(ctx context.Context, req Request) Decision {
	d := req.Destination
	op, found := Operation{}, false
	if c := t.Connectors[d.Name]; c != nil {
		var err error
		op, found, err = c.Operation(ctx, req)
		if err != nil {
			return Decision{Verdict: audit.Deny, Reason: "the request could not be matched to an operation", Error: err.Error()}
		}
	}
	if !found {
		if m, ok := d.Match(req.Method, req.Path); ok {
			op, found = Operation{Name: m.Operation, Params: m.Params, Target: m.Target}, true
		}
	}
	dec := Decision{Operation: op.Name, Target: ledger.TargetText(op.Params, op.Target)}
	what := "the operation " + op.Name
	if !found {
		what = "a request no rule names"
	}
	action := d.ActionFor(op.Name)
	from := "the table"
	if _, ok := d.Operations[op.Name]; !ok || op.Name == "" {
		from = "the destination's default"
	}
	switch action {
	case routes.Allow:
		dec.Verdict = audit.Allow
		dec.Reason = fmt.Sprintf("%s: %s allows it", what, from)
		return dec
	case routes.Ask:
	default:
		dec.Verdict = audit.Deny
		dec.Reason = fmt.Sprintf("%s: %s denies it", what, from)
		return dec
	}

	if t.Ledger == nil {
		dec.Verdict = audit.Deny
		dec.Reason = fmt.Sprintf("%s: %s asks about it, and there is no ledger", what, from)
		dec.Error = "no ledger"
		return dec
	}
	facts := ledger.Facts{
		Source:      req.Source,
		Destination: d.Name,
		Method:      req.Method,
		Path:        req.Path,
		Query:       req.Query,
		Operation:   op.Name,
		Params:      op.Params,
		Target:      op.Target,
		Body:        req.BodySummary,
		Fingerprint: fingerprint(req),
		Exact:       req.BodyComplete,
	}
	g, err := t.Ledger.Lookup(ctx, facts)
	if err != nil {
		dec.Verdict = audit.Deny
		dec.Reason = fmt.Sprintf("%s: %s asks about it, and the ledger could not be read, so there is no grant", what, from)
		dec.Error = err.Error()
		return dec
	}
	if g != nil {
		dec.Verdict = audit.Allow
		dec.Grant = g.ID
		dec.Reason = fmt.Sprintf("%s: %s asks about it, and the grant %s covers it", what, from, g.ID)
		return dec
	}
	a, created, err := t.Ledger.Hold(ctx, facts, req.Settings)
	if err != nil {
		dec.Verdict = audit.Deny
		dec.Reason = fmt.Sprintf("%s: %s asks about it, and the ledger could not hold it for the owner", what, from)
		dec.Error = err.Error()
		return dec
	}
	dec.Verdict = audit.Ask
	dec.Approval = a.ID
	dec.ApprovalCreated = created
	dec.Reason = fmt.Sprintf("%s: %s asks about it; held for the owner as %s", what, from, a.ID)
	return dec
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
