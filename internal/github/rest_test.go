package github_test

import (
	"strings"
	"testing"

	"github.com/yuanying/natsumi-sentinel/internal/audit"
)

func TestARESTReadGoesThroughAsARead(t *testing.T) {
	w := newWorld(t)
	for _, m := range []string{"GET", "HEAD"} {
		res, err := w.read("api.example.com", m, "/repos/o/r/pulls", "")
		if err != nil || !res.Read {
			t.Errorf("%s: %+v, %v", m, res, err)
		}
	}
	if len(w.gh.requests()) != 0 {
		t.Error("the gate asked upstream about a read")
	}
}

func TestARESTWriteIsNamedByTheRulesWithTheOwnerAndRepositoryWithoutCase(t *testing.T) {
	w := newWorld(t)
	res := w.must("api.example.com", "POST", "/repos/Example/R/issues/5/comments", `{"body":"hi"}`)
	if len(res.Operations) != 1 {
		t.Fatalf("operations = %+v", res.Operations)
	}
	op := res.Operations[0]
	if op.Name != "issue.comment" || params(op.Params) != "owner=example repo=r number=5" {
		t.Errorf("operation = %+v", op)
	}
}

func TestARESTWriteNoRuleNamesIsARawOperation(t *testing.T) {
	w := newWorld(t)
	res := w.must("api.example.com", "DELETE", "/repos/o/r/hooks/1", "")
	if len(res.Operations) != 1 || res.Operations[0].Name != "" {
		t.Errorf("operations = %+v", res.Operations)
	}
}

func TestAMergeWithoutTheHeadSHAIsRefused(t *testing.T) {
	w := newWorld(t)
	for _, body := range []string{`{"merge_method":"squash"}`, `{"sha":""}`, `{"sha":5}`, `not json`} {
		res, err := w.read("api.example.com", "PUT", "/repos/o/r/pulls/5/merge", body)
		if err != nil || res.Refusal == "" || !strings.Contains(res.Refusal, "SHA") {
			t.Errorf("%s: %+v, %v", body, res, err)
		}
	}
	req := w.request("api.example.com", "PUT", "/repos/o/r/pulls/5/merge", `{"sha":"abc"}`)
	req.BodyComplete = false
	if res, _ := w.c.Read(t.Context(), req); res.Refusal == "" {
		t.Error("a merge whose body was not read whole was not refused")
	}
}

func TestAMergeWithTheHeadSHAIsTheMergeOfThatSHA(t *testing.T) {
	w := newWorld(t)
	res := w.must("api.example.com", "PUT", "/repos/o/r/pulls/5/merge", `{"sha":"abc","merge_method":"squash"}`)
	op := res.Operations[0]
	if op.Name != "pr.merge" || params(op.Params) != "owner=o repo=r number=5 sha=abc" || strings.Join(op.Target, " ") != "owner repo number" {
		t.Errorf("operation = %+v", op)
	}
}

func TestATagMadeThroughRESTShowsItsCommitAndWhetherItIsOnTheDefaultBranch(t *testing.T) {
	w := newWorld(t)
	w.gh.repos["o/r"] = "main"
	w.gh.compare["main...abc"] = "behind"
	res := w.must("api.example.com", "POST", "/repos/o/r/git/refs", `{"ref":"refs/tags/v1.0.0","sha":"abc"}`)
	op := res.Operations[0]
	if op.Name != "tag.create" || params(op.Params) != "owner=o repo=r tag=v1.0.0 sha=abc" {
		t.Errorf("operation = %+v", op)
	}
	if params(op.Facts) != "commit=abc defaultBranch=main onDefaultBranch=true" {
		t.Errorf("facts = %s", params(op.Facts))
	}

	asked := w.gh.requests()
	if len(asked) != 2 {
		t.Fatalf("asked %d questions, want the repository and the compare", len(asked))
	}
	for _, r := range asked {
		if r.Header.Get("Authorization") != surrogate {
			t.Errorf("%s was asked with %q; want the request's own surrogate", r.URL.Path, r.Header.Get("Authorization"))
		}
	}
	if len(w.log.finished) != 2 {
		t.Fatalf("records = %d", len(w.log.finished))
	}
	rec := w.log.finished[1]
	if rec.Kind != audit.KindGate || rec.Source != "workspace" || rec.Name != "api.example.com" || rec.Method != "GET" || !strings.Contains(rec.Path, "/compare/") || rec.Status != 200 || rec.Reason == "" {
		t.Errorf("record = %+v", rec)
	}
}

func TestATagOnACommitOffTheDefaultBranchOrUnknownUpstreamSaysSo(t *testing.T) {
	w := newWorld(t)
	w.gh.repos["o/r"] = "main"
	w.gh.compare["main...abc"] = "diverged"
	res := w.must("api.example.com", "POST", "/repos/o/r/git/refs", `{"ref":"refs/tags/v1","sha":"abc"}`)
	if got := params(res.Operations[0].Facts); got != "commit=abc defaultBranch=main onDefaultBranch=false" {
		t.Errorf("diverged: %s", got)
	}
	res = w.must("api.example.com", "POST", "/repos/o/r/git/refs", `{"ref":"refs/tags/v1","sha":"def"}`)
	if got := params(res.Operations[0].Facts); got != "commit=def defaultBranch=main onDefaultBranch=unknown" {
		t.Errorf("unknown: %s", got)
	}
}

func TestWhenTheGatesQuestionIsNotAnsweredTheRequestIsNotNamed(t *testing.T) {
	w := newWorld(t)
	w.gh.fail = true
	if _, err := w.read("api.example.com", "POST", "/repos/o/r/git/refs", `{"ref":"refs/tags/v1","sha":"abc"}`); err == nil {
		t.Error("a 500 from upstream was taken")
	}
	if len(w.log.finished) != 1 || w.log.finished[0].Status != 500 || w.log.finished[0].Error == "" {
		t.Errorf("records = %+v", w.log.finished)
	}

	w = newWorld(t)
	w.gh.repos["o/r"] = "main"
	w.log.err = errTest
	if _, err := w.read("api.example.com", "POST", "/repos/o/r/git/refs", `{"ref":"refs/tags/v1","sha":"abc"}`); err == nil {
		t.Error("a question that could not be recorded was asked")
	}
	if len(w.gh.requests()) != 0 {
		t.Error("a question that could not be recorded reached upstream")
	}
}
