package e2e_test

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/yuanying/natsumi-sentinel/internal/audit"
	"github.com/yuanying/natsumi-sentinel/internal/authdclient"
	"github.com/yuanying/natsumi-sentinel/internal/notice"
)

// The fake upstream stands for Alertmanager behind a door that wants a
// bearer token.
func newAlertmanagerWorld(t *testing.T) *world {
	return newWorldWith(t, routesYAML, func(rw http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+realKey {
			rw.WriteHeader(http.StatusUnauthorized)
			return
		}
		rw.WriteHeader(http.StatusOK)
	})
}

func (w *world) sendNotice(url string) error {
	w.t.Helper()
	am, err := notice.NewAlertmanager(notice.AlertmanagerConfig{
		URL:       url,
		Surrogate: surrogate,
		Transport: w.authd,
		Log:       w.log,
	})
	if err != nil {
		w.t.Fatal(err)
	}
	return am.Send(context.Background(), []notice.Notice{{
		Type: notice.TypeFirstSeen, At: time.Now(),
		Labels:  map[string]string{"pair": "destination", "key": "api.example.com"},
		Summary: "First seen, a destination: api.example.com",
	}})
}

func (w *world) gateRecords() []*audit.Record {
	w.t.Helper()
	recs, err := w.log.List(context.Background(), audit.Query{Kind: audit.KindGate})
	if err != nil {
		w.t.Fatal(err)
	}
	return recs
}

func TestTheGatesNoticeHasItsSurrogateSwappedByAuthdAndReachesAlertmanager(t *testing.T) {
	w := newAlertmanagerWorld(t)
	if err := w.sendNotice("https://example.com/am"); err != nil {
		t.Fatalf("send = %v", err)
	}
	seen := w.upstreamSaw()
	if len(seen) != 1 {
		t.Fatalf("the upstream saw %d requests, want 1", len(seen))
	}
	r := seen[0]
	if r.Method != http.MethodPost || r.URL.Path != "/am/api/v2/alerts" {
		t.Errorf("the upstream saw %s %s", r.Method, r.URL.Path)
	}
	if got := r.Header.Get("Authorization"); got != "Bearer "+realKey {
		t.Errorf("the upstream got Authorization %q, want the real key", got)
	}
	body, _ := io.ReadAll(r.Body)
	if !strings.Contains(string(body), "SentinelFirstSeen") {
		t.Errorf("the upstream got %s", body)
	}
	recs := w.gateRecords()
	if len(recs) != 1 || recs[0].Status != http.StatusOK || recs[0].Error != "" {
		t.Errorf("the gate's records = %+v", recs)
	}
}

func TestTheGatesNoticeToAnUpstreamNotRegisteredIsRefusedByAuthdAndNotSwapped(t *testing.T) {
	w := newAlertmanagerWorld(t)
	err := w.sendNotice("https://unregistered.example.com")
	if err == nil {
		t.Fatal("send = nil to an upstream authd does not know")
	}
	if n := len(w.upstreamSaw()); n != 0 {
		t.Errorf("the upstream saw %d requests, want none", n)
	}
	recs := w.gateRecords()
	if len(recs) != 1 || !strings.Contains(recs[0].Error, string(authdclient.ReasonUpstreamNotRegistered)) {
		t.Errorf("the gate's records = %+v, want authd's refusal", recs)
	}
	if strings.Contains(err.Error(), surrogate) || strings.Contains(err.Error(), realKey) {
		t.Errorf("the error tells a surrogate or a key: %v", err)
	}
}
