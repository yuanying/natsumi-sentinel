package approvals

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/yuanying/natsumi-sentinel/internal/audit"
	"github.com/yuanying/natsumi-sentinel/internal/decide"
	"github.com/yuanying/natsumi-sentinel/internal/ledger"
	"github.com/yuanying/natsumi-sentinel/internal/routes"
	"github.com/yuanying/natsumi-sentinel/internal/upstream"
)

// This file is what the doors add for the destination grants
// (docs/approvals-api.md "宛先の許し").

// DestinationConfig turns the destination grants on in a door. Without
// one, the doors are as they were before the grants: the paths below are
// not there, and the workspace cannot ask for a destination.
type DestinationConfig struct {
	Routes func() *routes.Table
	// Fixed are the gate's own names, and SearchSuffixes those of the
	// workspace's resolver: neither is granted.
	Fixed          []string
	SearchSuffixes []string
	// Inside are the inside domains, told on what is shown.
	Inside upstream.Domains
	// Granted is told each grant given from the list of refused names,
	// once it has taken effect (docs/notices.md). May be nil.
	Granted func(*ledger.Grant)
}

func (dc *DestinationConfig) grantable(name string) error {
	return decide.Grantable(dc.Routes(), name, dc.Fixed, dc.SearchSuffixes)
}

// refusedName is one name of the list of refused names, as the owner
// reads it.
type refusedName struct {
	Source  string          `json:"source"`
	Name    string          `json:"name"`
	Domain  string          `json:"domain,omitempty"`
	Inside  bool            `json:"inside"`
	First   time.Time       `json:"first"`
	Last    time.Time       `json:"last"`
	Count   int64           `json:"count"`
	Summary string          `json:"summary"`
	Choices []ledger.Choice `json:"choices"`
	Options *ledger.Options `json:"options"`
}

// refusedList reads the refused names, leaving out the ones that cannot be
// granted now (the table may have taken them in since) and folding a name
// with a search suffix added into the same name without it, when that is
// on the list too: the workspace's resolver tried the suffix on the way to
// the name (docs/destination-grants.md).
func (dc *DestinationConfig) refusedList(ctx context.Context, l *ledger.Ledger, f ledger.RefusedFilter, limit int) ([]ledger.RefusedName, error) {
	f.Limit = 1000
	all, err := l.RefusedNames(ctx, f)
	if err != nil {
		return nil, err
	}
	have := map[string]bool{}
	for _, r := range all {
		have[r.Source+" "+r.Name] = true
	}
	var out []ledger.RefusedName
	for _, r := range all {
		if dc.grantable(r.Name) != nil || dc.folded(r, have) {
			continue
		}
		out = append(out, r)
		if len(out) == limit {
			break
		}
	}
	return out, nil
}

func (dc *DestinationConfig) folded(r ledger.RefusedName, have map[string]bool) bool {
	for _, sfx := range dc.SearchSuffixes {
		sfx = strings.TrimPrefix(routes.Normalize(sfx), ".")
		if base, ok := strings.CutSuffix(r.Name, "."+sfx); ok && sfx != "" && have[r.Source+" "+base] {
			return true
		}
	}
	return false
}

func (o *owner) listRefused(w http.ResponseWriter, r *http.Request) {
	dc := o.cfg.Destinations
	q := r.URL.Query()
	limit, err := intParam(q.Get("limit"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "limit: "+err.Error())
		return
	}
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	list, err := dc.refusedList(r.Context(), o.cfg.Ledger, ledger.RefusedFilter{Source: q.Get("source")}, int(limit))
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "the ledger could not be read")
		return
	}
	settings := dc.Routes().Approvals()
	out := []refusedName{}
	for _, rn := range list {
		choices, opts := ledger.RefusedChoices(rn.Name, settings)
		inside := dc.Inside.Inside(rn.Name)
		out = append(out, refusedName{
			Source: rn.Source, Name: rn.Name, Domain: rn.Domain, Inside: inside,
			First: rn.First, Last: rn.Last, Count: rn.Count,
			Summary: refusedSummary(rn, inside), Choices: choices, Options: opts,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"names": out})
}

// refusedSummary is the sentence the gate makes of a refused name's facts.
func refusedSummary(rn ledger.RefusedName, inside bool) string {
	times := "once"
	if rn.Count != 1 {
		times = fmt.Sprintf("%d times", rn.Count)
	}
	s := fmt.Sprintf("%s, not in the routing table, was refused in name resolution %s for %s, first at %s and last at %s",
		rn.Name, times, rn.Source, rn.First.UTC().Format(time.RFC3339), rn.Last.UTC().Format(time.RFC3339))
	if rn.Domain != "" {
		s += "; its registrable domain is " + rn.Domain
	}
	if inside {
		s += "; an inside name"
	}
	return s
}

type grantRefusedBody struct {
	Source  string               `json:"source"`
	Name    string               `json:"name"`
	Choice  string               `json:"choice"`
	Options *ledger.OptionAnswer `json:"options"`
}

func (o *owner) grantRefused(w http.ResponseWriter, r *http.Request) {
	dc := o.cfg.Destinations
	var body grantRefusedBody
	if err := decode(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	name := routes.Normalize(body.Name)
	if err := dc.grantable(name); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("%s cannot be granted: %v", name, err))
		return
	}
	rg := ledger.RefusedGrant{Source: body.Source, Name: name, Inside: dc.Inside.Inside(name), Settings: dc.Routes().Approvals(), Choice: body.Choice}
	if body.Options != nil {
		rg.Options = *body.Options
	}
	var at time.Time
	g, err := o.cfg.Ledger.GrantRefused(r.Context(), rg, func(g *ledger.Grant) error {
		at = o.cfg.Now()
		return o.cfg.Log.Write(context.WithoutCancel(r.Context()), &audit.Record{
			Time: at, Source: g.Source, Kind: audit.KindAnswer, Verdict: audit.Allow, Name: name, Grant: g.ID,
			Reason: fmt.Sprintf("the owner granted %s from the list of refused names with the choice %s and the options %s: %s",
				name, body.Choice, optionsText(chosenOf(g)), g.Summary),
		})
	})
	switch {
	case errors.Is(err, ledger.ErrNotFound):
		writeError(w, http.StatusNotFound, fmt.Sprintf("%s is not on the list of refused names of %q", name, body.Source))
		return
	case err != nil:
		writeLedgerError(w, err)
		return
	}
	if dc.Granted != nil {
		dc.Granted(g)
	}
	writeJSON(w, http.StatusCreated, map[string]any{"grant": g})
}

// chosenOf is the options a destination grant was given with.
func chosenOf(g *ledger.Grant) ledger.OptionAnswer {
	unit := string(ledger.UnitName)
	if g.Unit == ledger.UnitDomain {
		unit = "domain:" + g.Name
	}
	return ledger.OptionAnswer{Unit: unit, Handling: string(g.Handling), Access: string(g.Access)}
}

func optionsText(o ledger.OptionAnswer) string {
	s := "unit=" + o.Unit + " handling=" + o.Handling
	if o.Access != "" {
		s += " access=" + o.Access
	}
	return s
}

// refusedRecent is what the workspace reads of a name refused to it.
type refusedRecent struct {
	Name  string    `json:"name"`
	Last  time.Time `json:"last"`
	Count int64     `json:"count"`
}

// errNotGrantable is a destination that cannot be asked for: what the
// owner's approval could not let through, or what needs no approval.
var errNotGrantable = errors.New("not grantable")

// askDestinations makes an approval of the names the workspace asked for.
func (a *agent) askDestinations(w http.ResponseWriter, r *http.Request, items []askItem) {
	dc := a.cfg.Destinations
	if dc == nil {
		writeError(w, http.StatusBadRequest, "items: the gate gives no destination grants; a destination not in the routing table is added to the table by the owner")
		return
	}
	ctx := r.Context()
	seen := map[string]bool{}
	var facts []ledger.Facts
	for i, it := range items {
		name := routes.Normalize(it.Destination)
		if err := dc.grantable(name); err != nil {
			status := http.StatusBadRequest
			if errors.Is(err, decide.ErrTableDenies) {
				status = http.StatusForbidden
			}
			writeError(w, status, fmt.Sprintf("items[%d]: %s cannot be asked for: %v", i, name, err))
			return
		}
		if seen[name] {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("items[%d]: %s is given twice", i, name))
			return
		}
		seen[name] = true
		g, err := a.cfg.Ledger.LookupDestination(ctx, a.cfg.Source, name)
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "the ledger could not be read, so no approval was made")
			return
		}
		if g != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("items[%d]: the destination grant %s already covers %s; there is nothing to ask", i, g.ID, name))
			return
		}
		rn, err := a.cfg.Ledger.RefusedName(ctx, a.cfg.Source, name)
		if err != nil && !errors.Is(err, ledger.ErrNotFound) {
			writeError(w, http.StatusServiceUnavailable, "the ledger could not be read, so no approval was made")
			return
		}
		facts = append(facts, ledger.DestinationFacts(name, dc.Inside.Inside(name), rn))
	}
	ap, err := a.cfg.Ledger.AskDestinations(ctx, a.cfg.Source, facts, dc.Routes().Approvals(), func(ap *ledger.Approval) error {
		return a.cfg.Log.Write(context.WithoutCancel(ctx), &audit.Record{
			Time: a.cfg.Now(), Source: a.cfg.Source, Kind: audit.KindAgent, Verdict: audit.Ask,
			Name: ap.Items[0].Destination, Approval: ap.ID, Method: r.Method, Path: r.URL.Path,
			Reason: "the workspace asked beforehand: " + ap.Summary,
		})
	})
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "the request could not be recorded or kept, so no approval was made")
		return
	}
	writeJSON(w, http.StatusCreated, ap)
}
