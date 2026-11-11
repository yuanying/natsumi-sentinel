package github_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yuanying/natsumi-sentinel/internal/audit"
	"github.com/yuanying/natsumi-sentinel/internal/decide"
	"github.com/yuanying/natsumi-sentinel/internal/github"
	"github.com/yuanying/natsumi-sentinel/internal/routes"
)

const surrogate = "Bearer surrogate-for-the-test"

const table = `
destinations:
  - name: api.example.com
    treatment: open
    default: ask
    rules:
      - operation: issue.comment
        methods: [POST]
        path: /repos/{owner}/{repo}/issues/{number}/comments
      - operation: pr.merge
        methods: [PUT]
        path: /repos/{owner}/{repo}/pulls/{number}/merge
        body: {sha: "{sha}"}
        target: [owner, repo, number]
      - operation: tag.create
        methods: [POST]
        path: /repos/{owner}/{repo}/git/refs
        body: {ref: "refs/tags/{tag...}", sha: "{sha}"}
        target: [owner, repo, tag]
    github:
      graphql:
        - field: mergePullRequest
          operation: pr.merge
          target: [owner, repo, number]
        - field: createRef
          args: {name: "refs/tags/{tag...}"}
          operation: tag.create
          target: [owner, repo, tag]
        - field: addComment
          operation: issue.comment
  - name: git.example.com
    treatment: open
    default: ask
    github:
      api: api.example.com
      pushes:
        - operation: git.tag.create
          kinds: [create]
          ref: refs/tags/{tag...}
        - operation: git.branch.delete
          kinds: [delete]
        - operation: git.branch.force
          kinds: [force]
        - operation: git.branch.push
          kinds: [create, update]
          ref: refs/heads/{branch...}
`

// fakeGitHub answers the gate's own questions as GitHub would, from what
// a test sets, and keeps what it was asked.
type fakeGitHub struct {
	mu    sync.Mutex
	asked []*http.Request
	// nodes are answered to the GraphQL nodes query, by ID; a missing ID
	// is null.
	nodes map[string]map[string]any
	// compare gives the status of base...head, by "base...head"; a
	// missing pair is 404.
	compare map[string]string
	// repos give the default branch, by "owner/repo"; a missing one is
	// 404.
	repos map[string]string
	// fail makes every answer a 500.
	fail bool
}

func (f *fakeGitHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(strings.NewReader(string(body)))
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, r)
	if f.fail {
		http.Error(w, "down", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/graphql":
		var q struct {
			Variables struct {
				IDs []string `json:"ids"`
			} `json:"variables"`
		}
		_ = json.Unmarshal(body, &q)
		nodes := []any{}
		for _, id := range q.Variables.IDs {
			if n, ok := f.nodes[id]; ok {
				nodes = append(nodes, n)
			} else {
				nodes = append(nodes, nil)
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"nodes": nodes}})
	case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/compare/"):
		key := r.URL.Path[strings.Index(r.URL.Path, "/compare/")+len("/compare/"):]
		status, ok := f.compare[key]
		if !ok {
			http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
			return
		}
		_, _ = fmt.Fprintf(w, `{"url":"x","base_commit":{"sha":"b","commit":{"message":"m"}},"status":%q,"ahead_by":1,"files":[]}`, status)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/repos/"):
		branch, ok := f.repos[strings.TrimPrefix(r.URL.Path, "/repos/")]
		if !ok {
			http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
			return
		}
		_, _ = fmt.Fprintf(w, `{"name":"r","default_branch":%q}`, branch)
	default:
		http.Error(w, "unexpected", http.StatusTeapot)
	}
}

func (f *fakeGitHub) requests() []*http.Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*http.Request(nil), f.asked...)
}

// transport hands requests to a handler, as authd hands them to GitHub.
type transport struct{ h http.Handler }

func (t transport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme != "https" || r.URL.Host != "api.example.com:443" {
		return nil, fmt.Errorf("asked %s, want https://api.example.com:443", r.URL)
	}
	rec := httptest.NewRecorder()
	t.h.ServeHTTP(rec, r)
	return rec.Result(), nil
}

// memLog keeps the gate's own records.
type memLog struct {
	mu       sync.Mutex
	begun    []*audit.Record
	finished []*audit.Record
	err      error
}

func (m *memLog) Begin(_ context.Context, rec *audit.Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	m.begun = append(m.begun, rec)
	return nil
}

func (m *memLog) Finish(_ context.Context, rec *audit.Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.finished = append(m.finished, rec)
	return nil
}

type world struct {
	t   *testing.T
	gh  *fakeGitHub
	log *memLog
	c   *github.Connector
	tbl *routes.Table
}

func newWorld(t *testing.T) *world {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "r.yaml"), []byte(table), 0o600); err != nil {
		t.Fatal(err)
	}
	tbl, err := routes.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	w := &world{t: t, tbl: tbl, gh: &fakeGitHub{nodes: map[string]map[string]any{}, compare: map[string]string{}, repos: map[string]string{}}, log: &memLog{}}
	w.c = &github.Connector{
		Transport: transport{w.gh},
		Log:       w.log,
		Now:       func() time.Time { return time.Date(2026, 11, 11, 9, 0, 0, 0, time.UTC) },
	}
	return w
}

func (w *world) request(name, method, path, body string) decide.Request {
	w.t.Helper()
	d, ok := w.tbl.Lookup(name, 443)
	if !ok {
		w.t.Fatalf("no %s", name)
	}
	h := http.Header{}
	h.Set("Authorization", surrogate)
	return decide.Request{
		Source: "workspace", Destination: d, Settings: w.tbl.Approvals(), Port: 443,
		Method: method, Path: path, Header: h,
		Body: []byte(body), BodyComplete: true,
	}
}

func (w *world) read(name, method, path, body string) (decide.Result, error) {
	w.t.Helper()
	return w.c.Read(context.Background(), w.request(name, method, path, body))
}

// must reads a request the connector has to make operations of.
func (w *world) must(name, method, path, body string) decide.Result {
	w.t.Helper()
	res, err := w.read(name, method, path, body)
	if err != nil {
		w.t.Fatalf("Read: %v", err)
	}
	if res.Refusal != "" || res.Read {
		w.t.Fatalf("Read = %+v; want operations", res)
	}
	return res
}

func params(ps []routes.Param) string {
	var parts []string
	for _, p := range ps {
		parts = append(parts, p.Name+"="+p.Value)
	}
	return strings.Join(parts, " ")
}

func gql(query string, vars map[string]any) string {
	b, _ := json.Marshal(map[string]any{"query": query, "variables": vars})
	return string(b)
}

func repoNode(owner, name string) map[string]any {
	return map[string]any{"name": name, "owner": map[string]any{"login": owner}}
}
