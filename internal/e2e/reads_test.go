package e2e_test

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/yuanying/natsumi-sentinel/internal/audit"
	"github.com/yuanying/natsumi-sentinel/internal/notice"
)

// git fetches and clones with POST …/git-upload-pack, and gh reads with
// POST /graphql. The connector lets both through as reads; the records,
// the pairs and the daily summary count them as reads too, so that
// fetching a repository is not told as a write seen for the first time.
func TestAFetchAndAGraphQLQueryOnGitHubAreCountedAsReadsAndAPushAsAWrite(t *testing.T) {
	w := newGitHubWorld(t)
	start := time.Now().Add(-time.Minute)
	pairsOf := func(rec *audit.Record) string {
		var out []string
		for _, s := range notice.Pairs(rec) {
			out = append(out, s.Pair+"="+s.Key)
		}
		return fmt.Sprint(out)
	}

	resp, text := w.do("POST", "https://example.com/example-owner/project.git/git-upload-pack", pktLine("want "+headOID+"\n")+"0000"+pktLine("done\n"))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("a fetch = %d %q", resp.StatusCode, text)
	}
	rec := w.lastRecord()
	if !rec.Read || rec.Verdict != audit.Allow || rec.Operation != "" {
		t.Errorf("the fetch's record = %+v, want a read let through", rec)
	}
	if got := pairsOf(rec); got != "[destination=example.com]" {
		t.Errorf("the fetch's pairs = %s, want its destination only", got)
	}

	resp, text = w.do("POST", "https://example.com/graphql", `{"query":"query { viewer { login } }"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("a GraphQL query = %d %q", resp.StatusCode, text)
	}
	rec = w.lastRecord()
	if !rec.Read || rec.Verdict != audit.Allow {
		t.Errorf("the query's record = %+v, want a read let through", rec)
	}
	if got := pairsOf(rec); got != "[destination=example.com]" {
		t.Errorf("the query's pairs = %s, want its destination only", got)
	}

	resp, text = w.do("POST", "https://example.com/example-operator/project.git/git-receive-pack", receivePack(zeroOID+" "+headOID+" refs/heads/fix"))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("a push = %d %q", resp.StatusCode, text)
	}
	rec = w.lastRecord()
	if rec.Read {
		t.Errorf("the push's record = %+v, want a write", rec)
	}
	if got := pairsOf(rec); got != "[destination=example.com operation=example.com github.push.own owner=example-operator repo=project ref=refs/heads/fix]" {
		t.Errorf("the push's pairs = %s", got)
	}

	day, err := w.log.Day(context.Background(), start, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := fmt.Sprint(day.Writes), "[{example.com github.push.own  1}]"; got != want {
		t.Errorf("the day's writes = %s, want the push only", got)
	}
}
