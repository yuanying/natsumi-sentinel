package e2e_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yuanying/natsumi-sentinel/internal/audit"
	"github.com/yuanying/natsumi-sentinel/internal/gate"
)

// The fake upstream is GitHub's API and git on one name (its certificate
// is for example.com).
const githubYAML = `
destinations:
  - name: example.com
    treatment: open
    default: ask
    github:
      graphql:
        - field: mergePullRequest
          operation: github.pr.merge
          target: [owner, repo, number]
      pushes:
        - operation: github.ref.delete
          kinds: [delete]
        - operation: github.push.own
          kinds: [create, update]
          repository: example-operator/{name}
    rules:
      - operation: github.issue.create
        methods: [POST]
        path: /repos/{owner}/{repo}/issues
      - operation: github.pr.merge
        methods: [PUT]
        path: /repos/{owner}/{repo}/pulls/{number}/merge
        body: {sha: "{sha}"}
        target: [owner, repo, number]
    operations:
      github.pr.merge: ask
      github.push.own: allow
      github.ref.delete: deny
`

const (
	zeroOID = "0000000000000000000000000000000000000000"
	headOID = "1111111111111111111111111111111111111111"
)

func newGitHubWorld(t *testing.T) *world {
	return newWorldWith(t, githubYAML, func(rw http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		rw.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/graphql" && strings.Contains(string(body), "nodes(ids"):
			_, _ = fmt.Fprintf(rw, `{"data":{"nodes":[{"__typename":"PullRequest","number":7,"headRefOid":%q,"repository":{"name":"R","owner":{"login":"O"}}}]}}`, headOID)
		case r.URL.Path == "/graphql":
			_, _ = io.WriteString(rw, `{"data":{"viewer":{"login":"example-operator"}}}`)
		default:
			rw.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(rw, "from upstream")
		}
	})
}

func pktLine(s string) string { return fmt.Sprintf("%04x%s", len(s)+4, s) }

func receivePack(command string) string {
	return pktLine(command+"\x00report-status\n") + "0000" + "PACK\x00\x00\x00\x02pack data"
}

func TestARESTWriteOnGitHubIsAskedAndGoesThroughOnceAllowed(t *testing.T) {
	w := newGitHubWorld(t)
	const body = `{"title":"hi"}`
	resp, _ := w.do("POST", "https://example.com/repos/O/R/issues", body)
	id := resp.Header.Get(gate.ApprovalHeader)
	if resp.StatusCode != http.StatusForbidden || id == "" {
		t.Fatalf("first try = %d", resp.StatusCode)
	}
	w.answer(id, `{"answer":"allow","choice":"once"}`)
	resp, text := w.do("POST", "https://example.com/repos/O/R/issues", body)
	if resp.StatusCode != http.StatusCreated || text != "from upstream" {
		t.Fatalf("after the answer = %d %q", resp.StatusCode, text)
	}
	if rec := w.lastRecord(); rec.Operation != "github.issue.create" || rec.Target != "owner=o repo=r" {
		t.Errorf("record = %+v", rec)
	}
}

func TestAGraphQLReadOnGitHubGoesThroughWithTheRealKey(t *testing.T) {
	w := newGitHubWorld(t)
	resp, text := w.do("POST", "https://example.com/graphql", `{"query":"{ viewer { login } }"}`)
	if resp.StatusCode != http.StatusOK || !strings.Contains(text, "example-operator") {
		t.Fatalf("response = %d %q", resp.StatusCode, text)
	}
	seen := w.upstreamSaw()
	if len(seen) != 1 || seen[0].Header.Get("Authorization") != "Bearer "+realKey {
		t.Errorf("upstream saw %+v", seen)
	}
}

func TestAGraphQLMergeIsAskedAboutWhatTheGateLookedUpThroughAuthd(t *testing.T) {
	w := newGitHubWorld(t)
	q := fmt.Sprintf(`{"query":"mutation { mergePullRequest(input: {pullRequestId: \"PR_x\", expectedHeadOid: \"%s\"}) { clientMutationId } }"}`, headOID)
	resp, text := w.do("POST", "https://example.com/graphql", q)
	if resp.StatusCode != http.StatusForbidden || resp.Header.Get(gate.MarkHeader) != gate.MarkAsk {
		t.Fatalf("response = %d %q", resp.StatusCode, text)
	}
	if !strings.Contains(text, "owner=o repo=r number=7") {
		t.Errorf("the answer does not name what was looked up: %q", text)
	}
	seen := w.upstreamSaw()
	if len(seen) != 1 || seen[0].URL.Path != "/graphql" || seen[0].Header.Get("Authorization") != "Bearer "+realKey {
		t.Fatalf("upstream saw %+v; want the gate's question only, with the real key", seen)
	}
	asked, _ := io.ReadAll(seen[0].Body)
	if !strings.Contains(string(asked), "PR_x") || strings.Contains(string(asked), "mergePullRequest") {
		t.Errorf("the gate's question = %s", asked)
	}
	recs, _ := w.log.List(context.Background(), audit.Query{Kind: audit.KindGate})
	if len(recs) != 1 || recs[0].Source != "workspace" || recs[0].Status != http.StatusOK {
		t.Errorf("the gate's question was not recorded: %+v", recs)
	}

	ap := w.approval(resp.Header.Get(gate.ApprovalHeader))
	items, _ := ap["items"].([]any)
	item, _ := items[0].(map[string]any)
	if len(items) != 1 || item["targetText"] != "owner=o repo=r number=7" || !strings.Contains(fmt.Sprint(item["facts"]), headOID) {
		t.Errorf("approval = %v", ap)
	}
}

func TestAMergeWithoutItsSHAIsRefusedBeforeAnythingIsAsked(t *testing.T) {
	w := newGitHubWorld(t)
	resp, text := w.do("PUT", "https://example.com/repos/o/r/pulls/7/merge", `{"merge_method":"squash"}`)
	if resp.StatusCode != http.StatusForbidden || resp.Header.Get(gate.MarkHeader) != gate.MarkDeny || !strings.Contains(text, "SHA") {
		t.Fatalf("response = %d %q", resp.StatusCode, text)
	}
	if n := len(w.upstreamSaw()); n != 0 {
		t.Errorf("upstream saw %d requests", n)
	}
}

func TestAPushTheTableDeniesIsRefusedAndOneAskedIsInTheWorkspacesStatus(t *testing.T) {
	w := newGitHubWorld(t)
	resp, text := w.do("POST", "https://example.com/example-operator/project.git/git-receive-pack", receivePack(headOID+" "+zeroOID+" refs/heads/old"))
	if resp.StatusCode != http.StatusForbidden || resp.Header.Get(gate.MarkHeader) != gate.MarkDeny {
		t.Fatalf("a delete = %d %q", resp.StatusCode, text)
	}
	rec := w.lastRecord()
	if rec.Operation != "github.ref.delete" || rec.Request == nil || rec.Request.Text != headOID+" "+zeroOID+" refs/heads/old\n" {
		t.Errorf("record = %+v; want the commands only", rec)
	}

	resp, _ = w.do("POST", "https://example.com/example-owner/project.git/git-receive-pack", receivePack(zeroOID+" "+headOID+" refs/heads/fix"))
	id := resp.Header.Get(gate.ApprovalHeader)
	if resp.StatusCode != http.StatusForbidden || id == "" {
		t.Fatalf("a push elsewhere = %d", resp.StatusCode)
	}
	// git does not show the 403's body: the workspace finds the approval
	// on its own door.
	rr := httptest.NewRecorder()
	w.agent.ServeHTTP(rr, httptest.NewRequest("GET", "/v1/status", nil))
	var status struct {
		Approvals []struct {
			ID string `json:"id"`
		} `json:"approvals"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &status)
	if len(status.Approvals) != 1 || status.Approvals[0].ID != id {
		t.Errorf("status = %s; want %s", rr.Body.String(), id)
	}

	resp, text = w.do("POST", "https://example.com/example-operator/project.git/git-receive-pack", receivePack(zeroOID+" "+headOID+" refs/heads/fix"))
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("a push to its own repository = %d %q", resp.StatusCode, text)
	}
}

func (w *world) approval(id string) map[string]any {
	w.t.Helper()
	rr := httptest.NewRecorder()
	w.owner.ServeHTTP(rr, httptest.NewRequest("GET", "/v1/approvals/"+id, nil))
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return out
}
