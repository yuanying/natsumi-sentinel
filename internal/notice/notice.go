// Package notice tells the owner what is out of the ordinary, without a
// judge (docs/adr/0006, docs/notices.md): each pair the gate sees go
// through for the first time, and once a day a summary of the day.
//
// The notices go to Alertmanager, through authd like any other request
// out of the gate (docs/adr/0002), and Alertmanager takes them to the
// owner's channel. Without Alertmanager they are only logged, and the gate
// runs on: notices are never a reason to stop it.
//
// A notice holds what was done, to what and where, and how many times:
// never a key, a surrogate or the body of a request.
package notice

import (
	"net/http"
	"time"

	"github.com/yuanying/natsumi-sentinel/internal/audit"
)

// The types of notice.
const (
	// TypeFirstSeen tells one pair seen for the first time.
	TypeFirstSeen = "first-seen"
	// TypeDailySummary tells what a day's records count up to.
	TypeDailySummary = "daily-summary"
)

// Notice is one thing to tell.
type Notice struct {
	Type string
	// At is when what it tells happened.
	At time.Time
	// Labels tell it apart from other notices of its type.
	Labels map[string]string
	// Summary is one line; Description may be longer.
	Summary     string
	Description string
}

// The pairs that are told the first time they are seen.
const (
	// PairDestination is a name in the routing table that a request went
	// through to.
	PairDestination = "destination"
	// PairWrite is a write let through: its destination, method and
	// path.
	PairWrite = "write"
	// PairPassthrough is an address and port passed straight through.
	PairPassthrough = "passthrough"
	// PairDeniedName is a name refused in name resolution.
	PairDeniedName = "denied-name"
)

// Pairs returns the pairs a record is, at its time and with its id. A
// record of something that was not let through is no pair, apart from a
// name refused in name resolution.
//
// A write is its name, method and path: the records have no operation or
// target of their own yet. The query is not part of it.
func Pairs(rec *audit.Record) []audit.Seen {
	seen := func(pair, key string) audit.Seen {
		return audit.Seen{Pair: pair, Key: key, First: rec.Time, Record: rec.ID}
	}
	switch {
	case rec.Kind == audit.KindHTTP && rec.Verdict == audit.Allow:
		out := []audit.Seen{seen(PairDestination, rec.Name)}
		if isWrite(rec.Method) {
			out = append(out, seen(PairWrite, rec.Name+" "+rec.Method+" "+rec.Path))
		}
		return out
	case rec.Kind == audit.KindPassthrough && rec.Verdict == audit.Allow:
		return []audit.Seen{seen(PairPassthrough, rec.Address)}
	case rec.Kind == audit.KindDNS && rec.Verdict == audit.Deny && rec.Name != "":
		return []audit.Seen{seen(PairDeniedName, rec.Name)}
	}
	return nil
}

func isWrite(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return false
	}
	return true
}
