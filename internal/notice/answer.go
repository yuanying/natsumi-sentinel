package notice

import (
	"fmt"
	"strings"
	"time"

	"github.com/yuanying/natsumi-sentinel/internal/ledger"
)

// Answered is the notice of an answer of the owner's the gate took
// (docs/adr/0006: so that the owner sees an approval the server made up).
// It tells the operations, their targets, the scope and when it ends, and
// never a query, a body or anything the workspace wrote about why.
func Answered(a *ledger.Approval) Notice {
	word := string(a.State)
	at := a.Created
	if a.Answered != nil {
		at = *a.Answered
	}
	summary := fmt.Sprintf("The owner %s %s", word, a.ID)
	if len(a.Items) > 0 {
		summary += ": " + factsText(a.Items[0])
		if len(a.Items) > 1 {
			summary += fmt.Sprintf(" and %d more", len(a.Items)-1)
		}
	}

	var b strings.Builder
	held := "a request held"
	switch a.Kind {
	case ledger.KindBeforehand:
		held = "operations asked for beforehand"
	case ledger.KindDestination:
		held = "destinations asked for beforehand"
	}
	fmt.Fprintf(&b, "The owner %s %s, %s for %s, at %s.", word, a.ID, held, a.Source, stamp(at))
	if a.State == ledger.Allowed {
		for _, c := range a.Choices {
			if c.ID == a.Choice {
				scope := scopeText(c, at)
				if o := a.Chosen; o != nil {
					scope += ", " + optionsText(o.Unit, o.Handling, o.Access)
				}
				summary += "; " + scope
				fmt.Fprintf(&b, " The choice %s: %s.", c.ID, scope)
			}
		}
		if len(a.Grants) > 0 {
			fmt.Fprintf(&b, " Grants: %s.", strings.Join(a.Grants, " "))
		}
	}
	b.WriteString("\n")
	for _, f := range a.Items {
		b.WriteString("  " + clip(factsText(f), maxLabel) + "\n")
	}
	return Notice{
		Type: TypeAnswer,
		At:   at,
		Labels: map[string]string{
			"answer":   word,
			"approval": a.ID,
			"source":   a.Source,
		},
		Summary:     clip(summary, maxLabel),
		Description: clip(b.String(), maxDescription),
	}
}

// GrantedFromList is the notice of the owner granting a name from the list
// of refused names, at the time given: an answer without an approval.
func GrantedFromList(g *ledger.Grant, at time.Time) Notice {
	what := grantText(g)
	return Notice{
		Type: TypeAnswer,
		At:   at,
		Labels: map[string]string{
			"answer":   string(ledger.Allowed),
			"approval": "",
			"grant":    g.ID,
			"source":   g.Source,
		},
		Summary: clip(fmt.Sprintf("The owner granted %s from the list of refused names: %s", g.ID, what), maxLabel),
		Description: clip(fmt.Sprintf("The owner gave the destination grant %s from the list of refused names, for %s, at %s, %s: %s.",
			g.ID, g.Source, stamp(at), endText(g), what), maxDescription),
	}
}

// grantText tells what a grant covers: an operation grant's operation and
// target, or a destination grant's name and options.
func grantText(g *ledger.Grant) string {
	if g.Kind != ledger.GrantDestination {
		return operationOn(g.Destination, g.Operation, g.Target, g.Method, g.Path)
	}
	unit := "name"
	if g.Unit == ledger.UnitDomain {
		unit = "domain:" + g.Name
	}
	return "the destination " + g.Name + " (" + optionsText(unit, string(g.Handling), string(g.Access)) + ")"
}

func optionsText(unit, handling, access string) string {
	s := "unit=" + unit + " handling=" + handling
	if access != "" {
		s += " access=" + access
	}
	return s
}

func endText(g *ledger.Grant) string {
	if g.Expires == nil {
		return "with no end"
	}
	return "ending at " + stamp(*g.Expires)
}

// Revoked is the notice of the owner revoking a grant, at the time given.
func Revoked(g *ledger.Grant, at time.Time) Notice {
	what := grantText(g)
	end := "with no end"
	if g.Expires != nil {
		end = "ending at " + stamp(*g.Expires)
	}
	return Notice{
		Type: TypeAnswer,
		At:   at,
		Labels: map[string]string{
			"answer":   "revoked",
			"approval": g.Approval,
			"grant":    g.ID,
			"source":   g.Source,
		},
		Summary: clip(fmt.Sprintf("The owner revoked %s: %s", g.ID, what), maxLabel),
		Description: clip(fmt.Sprintf("The owner revoked %s, of %s for %s, at %s. It was a %s grant made at %s, %s, for %s.",
			g.ID, g.Approval, g.Source, stamp(at), g.Scope, stamp(g.Created), end, what), maxDescription),
	}
}

func factsText(f ledger.Facts) string {
	if f.Operation == "" && f.Method == "" {
		return "the destination " + f.Destination
	}
	return operationOn(f.Destination, f.Operation, f.TargetText, f.Method, f.Path)
}

// operationOn tells an operation and its target on a destination, or a raw
// operation by its method and path.
func operationOn(dest, op, target, method, path string) string {
	switch {
	case op != "" && target != "":
		return op + " (" + target + ") on " + dest
	case op != "":
		return op + " on " + dest
	}
	return method + " " + path + " on " + dest
}

// scopeText tells how far a choice reaches and until when, for a grant
// made at at.
func scopeText(c ledger.Choice, at time.Time) string {
	end := at.Add(time.Duration(c.Seconds) * time.Second)
	switch {
	case c.Scope == ledger.ScopeOnce:
		return "once, to be used by " + stamp(end)
	case c.Seconds == 0:
		return string(c.Scope) + ", with no end"
	}
	return string(c.Scope) + ", until " + stamp(end)
}

func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339) }
