package gate_test

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/yuanying/natsumi-sentinel/internal/audit"
	"github.com/yuanying/natsumi-sentinel/internal/decide"
)

func (e *env) setDecision(d decide.Decision) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.decider = deciderFunc(func(context.Context, decide.Request) decide.Decision { return d })
}

func TestARefusalThatIsNotTheTablesDoesNotSendTheOwnerToTheTable(t *testing.T) {
	e := newEnv(t, 1)
	e.setDecision(decide.Decision{Verdict: audit.Deny, Fixed: true, Reason: "refused: the document has two mutations"})
	resp, err := e.client().Post("https://api.example.com/graphql", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(body), "two mutations") || strings.Contains(string(body), "routing table") {
		t.Errorf("%d %q", resp.StatusCode, body)
	}
}

func TestWhatTheDecisionKeepsOfTheBodyIsRecordedInPlaceOfTheBodyWithItsSizeAndHash(t *testing.T) {
	e := newEnv(t, 1)
	var got []byte
	e.setUpstream(func(w http.ResponseWriter, r *http.Request) {
		got, _ = io.ReadAll(r.Body)
	})
	e.setDecision(decide.Decision{Verdict: audit.Allow, Reason: "a push", Request: &audit.Body{Text: "commands\n"}})
	body := "commands\n" + strings.Repeat("P", 100)
	resp, err := e.client().Post("https://api.example.com/o/r.git/git-receive-pack", "application/x-git-receive-pack-request", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if string(got) != body {
		t.Errorf("upstream got %d bytes, want the whole body", len(got))
	}
	rec := e.log.waitFor(t, func(r *audit.Record) bool { return r.Kind == audit.KindHTTP })
	if rec.Request == nil || rec.Request.Text != "commands\n" || rec.Request.Size != int64(len(body)) || rec.Request.SHA256 == "" || rec.Request.Binary {
		t.Errorf("record's body = %+v", rec.Request)
	}

	e.setDecision(decide.Decision{Verdict: audit.Deny, Reason: "denied", Request: &audit.Body{Text: "commands\n"}})
	resp, err = e.client().Post("https://api.example.com/o/r.git/git-receive-pack", "application/x-git-receive-pack-request", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	rec = e.log.waitFor(t, func(r *audit.Record) bool { return r.Kind == audit.KindHTTP && r.Verdict == audit.Deny })
	if rec.Request == nil || rec.Request.Text != "commands\n" {
		t.Errorf("a denied push's body = %+v", rec.Request)
	}
}

func TestARequestTheDecisionCallsAReadIsRecordedAsARead(t *testing.T) {
	e := newEnv(t, 1)
	e.setDecision(decide.Decision{Verdict: audit.Allow, Reason: "a read: the connector lets reads through", Read: true})
	resp, err := e.client().Post("https://api.example.com/o/r.git/git-upload-pack", "application/x-git-upload-pack-request", strings.NewReader("0000"))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	rec := e.log.waitFor(t, func(r *audit.Record) bool { return r.Kind == audit.KindHTTP })
	if rec.Method != "POST" || !rec.Read || rec.Verdict != audit.Allow {
		t.Errorf("record = %+v, want a POST recorded as a read", rec)
	}
}

func TestAWriteIsNotRecordedAsARead(t *testing.T) {
	e := newEnv(t, 1)
	resp, err := e.client().Post("https://api.example.com/repos/o/r/issues", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	rec := e.log.waitFor(t, func(r *audit.Record) bool { return r.Kind == audit.KindHTTP })
	if rec.Read {
		t.Errorf("record = %+v, want a write", rec)
	}
}
