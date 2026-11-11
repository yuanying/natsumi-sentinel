// Package decide is where the gate asks whether a request read on an open
// destination may go out.
//
// The Decider is the one seam the rules, the asking and the grants of
// docs/adr/0004 plug into later. What is here decides by each
// destination's default only.
package decide

import (
	"context"
	"net/http"

	"github.com/yuanying/natsumi-sentinel/internal/audit"
	"github.com/yuanying/natsumi-sentinel/internal/routes"
)

// Request is what the gate knows about a request when it decides.
type Request struct {
	// Source is the listener the connection came in on.
	Source string
	// Destination is the open destination, as the routing table has it.
	Destination routes.Destination
	Port        uint16
	Method      string
	Path        string
	Query       string
	Header      http.Header
	// Body is the start of the request body, up to the audit body limit.
	// BodyComplete is false when the body goes on past it.
	Body         []byte
	BodyComplete bool
}

// Decision is the answer: allow or deny, and why.
type Decision struct {
	Verdict audit.Verdict
	Reason  string
}

// Decider decides on a request.
type Decider interface {
	Decide(ctx context.Context, req Request) Decision
}

// Defaults decides by the destination's default.
type Defaults struct{}

// Decide implements Decider.
func (Defaults) Decide(_ context.Context, req Request) Decision {
	switch req.Destination.Default {
	case routes.Allow:
		return Decision{Verdict: audit.Allow, Reason: "the destination's default is allow"}
	case routes.Deny:
		return Decision{Verdict: audit.Deny, Reason: "the destination's default is deny"}
	default:
		return Decision{Verdict: audit.Deny, Reason: "the destination has no default"}
	}
}
