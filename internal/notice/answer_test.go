package notice_test

import (
	"strings"
	"testing"
	"time"

	"github.com/yuanying/natsumi-sentinel/internal/audit"
	"github.com/yuanying/natsumi-sentinel/internal/ledger"
	"github.com/yuanying/natsumi-sentinel/internal/notice"
	"github.com/yuanying/natsumi-sentinel/internal/routes"
)

// mergeFacts is a held request to merge a PR, with a query and a body the
// notices must never carry.
func mergeFacts(number string) ledger.Facts {
	return ledger.Facts{
		Destination: "api.example.com", Method: "PUT",
		Path: "/repos/o/r/pulls/" + number + "/merge", Query: "token=never-told",
		Operation:  "pulls.merge",
		Params:     []routes.Param{{Name: "owner", Value: "o"}, {Name: "repo", Value: "r"}, {Name: "number", Value: number}},
		Target:     []string{"owner", "repo"},
		TargetText: "owner=o repo=r",
		Body:       &audit.Body{Text: "a body never told", Size: 17},
	}
}

func answered(state ledger.State, choice ledger.Choice, items ...ledger.Facts) *ledger.Approval {
	when := at
	a := &ledger.Approval{
		ID: "ap-1", Kind: ledger.KindRequest, State: state, Source: "workspace",
		Created: at.Add(-time.Hour), Expires: at.Add(23 * time.Hour),
		Summary: "PUT https://api.example.com/repos/o/r/pulls/5/merge?token=never-told; a body never told",
		Items:   items, Answered: &when,
		Choices: []ledger.Choice{choice},
	}
	if state == ledger.Allowed {
		a.Choice = choice.ID
		for range items {
			a.Grants = append(a.Grants, "gr-"+string(rune('a'+len(a.Grants))))
		}
	}
	return a
}

func wantTold(t *testing.T, n notice.Notice, says ...string) {
	t.Helper()
	all := n.Summary + "\n" + n.Description
	for k, v := range n.Labels {
		all += "\n" + k + "=" + v
	}
	for _, s := range says {
		if !strings.Contains(all, s) {
			t.Errorf("the notice does not say %q:\n%s", s, all)
		}
	}
	for _, never := range []string{"never-told", "a body never told", "/pulls/"} {
		if strings.Contains(all, never) {
			t.Errorf("the notice tells %q:\n%s", never, all)
		}
	}
	if len(n.Summary) > 256 || len(n.Description) > 2048 {
		t.Errorf("the notice is too long: %d, %d", len(n.Summary), len(n.Description))
	}
}

func TestAnAllowedAnswerIsToldWithTheOperationTheTargetTheScopeAndTheEnd(t *testing.T) {
	hour := ledger.Choice{ID: "1h", Scope: ledger.ScopeTimed, Seconds: 3600, Label: "pulls.merge (owner=o repo=r) on api.example.com for 1h"}
	n := notice.Answered(answered(ledger.Allowed, hour, mergeFacts("5")))
	if n.Type != notice.TypeAnswer || !n.At.Equal(at) {
		t.Errorf("notice = %+v", n)
	}
	for k, v := range map[string]string{"answer": "allowed", "approval": "ap-1", "source": "workspace"} {
		if n.Labels[k] != v {
			t.Errorf("label %s = %q, want %q", k, n.Labels[k], v)
		}
	}
	wantTold(t, n,
		"The owner allowed ap-1: pulls.merge (owner=o repo=r) on api.example.com",
		"timed",
		"until 2026-11-11T10:30:00Z",
		"gr-a",
		"workspace",
	)
}

func TestAnAllowedAnswerForOneRequestIsToldWithWhenItMustBeUsedBy(t *testing.T) {
	once := ledger.Choice{ID: "once", Scope: ledger.ScopeOnce, Seconds: 600, Label: "this request only, once, if made again within 10m"}
	n := notice.Answered(answered(ledger.Allowed, once, mergeFacts("5")))
	wantTold(t, n, "once", "used by 2026-11-11T09:40:00Z")
}

func TestAnAllowedAnswerWithNoEndSaysSo(t *testing.T) {
	forever := ledger.Choice{ID: "forever", Scope: ledger.ScopeTimed, Seconds: 0, Label: "pulls.merge (owner=o repo=r) on api.example.com with no end"}
	n := notice.Answered(answered(ledger.Allowed, forever, mergeFacts("5")))
	wantTold(t, n, "forever", "with no end")
}

func TestARawOperationIsToldByItsMethodAndPath(t *testing.T) {
	hour := ledger.Choice{ID: "1h", Scope: ledger.ScopeTimed, Seconds: 3600}
	n := notice.Answered(answered(ledger.Allowed, hour, ledger.Facts{Destination: "api.example.com", Method: "POST", Path: "/markdown", Query: "token=never-told"}))
	wantTold(t, n, "POST /markdown on api.example.com")
}

func TestADeniedAnswerIsToldWithWhatWasDenied(t *testing.T) {
	n := notice.Answered(answered(ledger.Denied, ledger.Choice{ID: "1h", Scope: ledger.ScopeTimed, Seconds: 3600}, mergeFacts("5")))
	if n.Labels["answer"] != "denied" {
		t.Errorf("labels = %v", n.Labels)
	}
	wantTold(t, n, "The owner denied ap-1: pulls.merge (owner=o repo=r) on api.example.com")
	if strings.Contains(n.Description, "until") {
		t.Errorf("a denial tells an end:\n%s", n.Description)
	}
}

func TestAnAnswerToSeveralOperationsAskedBeforehandTellsEachOfThem(t *testing.T) {
	once := ledger.Choice{ID: "once", Scope: ledger.ScopeOnce, Seconds: 600}
	second := mergeFacts("6")
	second.Operation, second.TargetText = "issues.create", "owner=o repo=s"
	a := answered(ledger.Allowed, once, mergeFacts("5"), second)
	a.Kind = ledger.KindBeforehand
	n := notice.Answered(a)
	wantTold(t, n,
		"The owner allowed ap-1: pulls.merge (owner=o repo=r) on api.example.com and 1 more",
		"issues.create (owner=o repo=s) on api.example.com",
		"gr-a", "gr-b",
		"beforehand",
	)
}

func TestARevocationIsToldWithTheGrantItEnded(t *testing.T) {
	end := at.Add(time.Hour)
	g := &ledger.Grant{
		ID: "gr-1", Approval: "ap-1", Source: "workspace", Scope: ledger.ScopeOnce, Created: at.Add(-time.Minute), Expires: &end,
		Summary:     "the one request PUT https://api.example.com/repos/o/r/pulls/5/merge?token=never-told",
		Destination: "api.example.com", Operation: "pulls.merge", Target: "owner=o repo=r",
		Method: "PUT", Path: "/repos/o/r/pulls/5/merge",
	}
	n := notice.Revoked(g, at)
	if n.Type != notice.TypeAnswer || !n.At.Equal(at) {
		t.Errorf("notice = %+v", n)
	}
	for k, v := range map[string]string{"answer": "revoked", "approval": "ap-1", "grant": "gr-1", "source": "workspace"} {
		if n.Labels[k] != v {
			t.Errorf("label %s = %q, want %q", k, n.Labels[k], v)
		}
	}
	wantTold(t, n, "The owner revoked gr-1: pulls.merge (owner=o repo=r) on api.example.com", "once", "2026-11-11T10:30:00Z")
}
