package ledger_test

import (
	"context"
	"strings"
	"testing"

	"github.com/yuanying/natsumi-sentinel/internal/ledger"
	"github.com/yuanying/natsumi-sentinel/internal/routes"
)

// pushRef is one ref of a push, held with its own fingerprint.
func pushRef(ref string) ledger.Facts {
	return ledger.Facts{
		Source:      "workspace",
		Destination: "git.example.com",
		Method:      "POST",
		Path:        "/o/r.git/git-receive-pack",
		Operation:   "git.push",
		Params:      []routes.Param{{Name: "owner", Value: "o"}, {Name: "repo", Value: "r"}, {Name: "ref", Value: ref}},
		Target:      []string{"owner", "repo", "ref"},
		Fingerprint: "fp-push-" + ref,
		Exact:       true,
	}
}

func TestSeveralRequestsHeldTogetherAreOneApprovalWithAnItemEach(t *testing.T) {
	l, _, _ := open(t)
	ctx := context.Background()
	a, created, err := l.HoldAll(ctx, []ledger.Facts{pushRef("refs/heads/a"), pushRef("refs/heads/b")}, settings)
	if err != nil || !created {
		t.Fatalf("HoldAll = %v, %v", created, err)
	}
	if len(a.Items) != 2 || a.Items[1].TargetText != "owner=o repo=r ref=refs/heads/b" {
		t.Errorf("items = %+v", a.Items)
	}
	if !strings.Contains(a.Summary, "refs/heads/a") || !strings.Contains(a.Summary, "refs/heads/b") {
		t.Errorf("summary = %q; want both refs", a.Summary)
	}
	if got := choiceIDs(a); !eq(got, []string{"once", "1h", "forever"}) {
		t.Errorf("choices = %v", got)
	}
	again, created, _ := l.HoldAll(ctx, []ledger.Facts{pushRef("refs/heads/a"), pushRef("refs/heads/b")}, settings)
	if created || again.ID != a.ID || again.Requests != 2 {
		t.Errorf("the same requests again: %s created=%v requests=%d", again.ID, created, again.Requests)
	}

	if _, err := l.Answer(ctx, a.ID, ledger.Answer{Allow: true, Choice: "once"}, nil); err != nil {
		t.Fatal(err)
	}
	grants, err := l.LookupAll(ctx, []ledger.Facts{pushRef("refs/heads/a"), pushRef("refs/heads/b")})
	if err != nil || grants[0] == nil || grants[1] == nil {
		t.Fatalf("LookupAll = %v, %v", grants, err)
	}
	if grants, _ := l.LookupAll(ctx, []ledger.Facts{pushRef("refs/heads/a")}); grants[0] != nil {
		t.Error("a grant of one request was used twice")
	}
}

func TestAGrantOfOneRequestIsNotUsedUpWhenAnotherRequestBesideItHasNone(t *testing.T) {
	l, _, _ := open(t)
	ctx := context.Background()
	a, _, _ := l.HoldAll(ctx, []ledger.Facts{pushRef("refs/heads/a")}, settings)
	if _, err := l.Answer(ctx, a.ID, ledger.Answer{Allow: true, Choice: "once"}, nil); err != nil {
		t.Fatal(err)
	}
	grants, err := l.LookupAll(ctx, []ledger.Facts{pushRef("refs/heads/a"), pushRef("refs/heads/b")})
	if err != nil {
		t.Fatal(err)
	}
	if grants[0] == nil || grants[1] != nil {
		t.Fatalf("grants = %v; want the first only", grants)
	}
	grants, _ = l.LookupAll(ctx, []ledger.Facts{pushRef("refs/heads/a")})
	if grants[0] == nil {
		t.Error("the grant was used up although the push did not go through")
	}
}

func TestTheLookedUpFactsAreShownButNotMatched(t *testing.T) {
	l, _, _ := open(t)
	ctx := context.Background()
	f := merge("5")
	f.Facts = []routes.Param{{Name: "head", Value: "abc"}}
	a, _, err := l.Hold(ctx, f, settings)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Items[0].Facts) != 1 || !strings.Contains(a.Summary, "head=abc") {
		t.Errorf("approval = %+v", a)
	}
}

func TestAGrantAskedForBeforehandMatchesTheParametersInAnyOrder(t *testing.T) {
	l, _, _ := open(t)
	ctx := context.Background()
	item := ledger.Facts{
		Destination: "api.example.com",
		Operation:   "pulls.merge",
		Params:      []routes.Param{{Name: "owner", Value: "o"}, {Name: "repo", Value: "r"}, {Name: "number", Value: "5"}, {Name: "sha", Value: "abc"}},
		Target:      []string{"owner", "repo", "number"},
	}
	a, err := l.Ask(ctx, "workspace", []ledger.Facts{item}, settings, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Answer(ctx, a.ID, ledger.Answer{Allow: true, Choice: "once"}, nil); err != nil {
		t.Fatal(err)
	}
	req := merge("5")
	req.Params = []routes.Param{{Name: "sha", Value: "abc"}, {Name: "number", Value: "5"}, {Name: "owner", Value: "o"}, {Name: "repo", Value: "r"}}
	req.Target = []string{"owner", "repo", "number"}
	if g, err := l.Lookup(ctx, req); err != nil || g == nil {
		t.Errorf("Lookup = %v, %v; the same parameters in another order", g, err)
	}
}
