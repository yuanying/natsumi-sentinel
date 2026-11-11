package audit_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/yuanying/natsumi-sentinel/internal/audit"
)

func TestADaysWritesAndRefusalsAreCountedFromTheRecords(t *testing.T) {
	l, _, _ := openLog(t)
	ctx := context.Background()
	write := func(offset time.Duration, rec audit.Record) {
		t.Helper()
		rec.Time = at.Add(offset)
		if err := l.Write(ctx, &rec); err != nil {
			t.Fatal(err)
		}
	}
	http := func(name, method, path string, v audit.Verdict, reason string) audit.Record {
		return audit.Record{Kind: audit.KindHTTP, Treatment: "open", Name: name, Method: method, Path: path, Verdict: v, Reason: reason}
	}
	// In the day.
	write(time.Minute, http("api.example.com", "POST", "/repos/o/r/issues", audit.Allow, ""))
	write(2*time.Minute, http("api.example.com", "POST", "/repos/o/r/issues/1/comments", audit.Allow, ""))
	write(3*time.Minute, http("api.example.com", "PATCH", "/repos/o/r/issues/1", audit.Allow, ""))
	write(4*time.Minute, http("cluster.example.com", "POST", "/api/v1/namespaces/a/pods", audit.Allow, ""))
	write(5*time.Minute, http("api.example.com", "GET", "/repos/o/r", audit.Allow, ""))
	write(6*time.Minute, http("api.example.com", "DELETE", "/repos/o/r", audit.Deny, "the destination's default is deny"))
	write(7*time.Minute, http("api.example.com", "DELETE", "/repos/o/r", audit.Deny, "the destination's default is deny"))
	write(8*time.Minute, audit.Record{Kind: audit.KindDNS, Name: "made-up.example.net", Verdict: audit.Deny, Reason: "not an open destination"})
	write(9*time.Minute, audit.Record{Kind: audit.KindConfig, Verdict: audit.Deny, Reason: "the routing table was not taken"})
	write(10*time.Minute, audit.Record{Kind: audit.KindGate, Name: "alerts.example.com", Method: "POST", Path: "/api/v2/alerts", Verdict: audit.Allow})
	// Outside it.
	write(-time.Minute, http("api.example.com", "POST", "/repos/o/r/issues", audit.Allow, ""))
	write(24*time.Hour, http("api.example.com", "DELETE", "/repos/o/r", audit.Deny, "x"))

	day, err := l.Day(ctx, at, at.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := fmt.Sprint(day.Writes), "[{api.example.com POST 2} {api.example.com PATCH 1} {cluster.example.com POST 1}]"; got != want {
		t.Errorf("writes = %s, want %s", got, want)
	}
	if got, want := fmt.Sprint(day.Refusals), "[{deny http api.example.com DELETE /repos/o/r the destination's default is deny 2} {deny dns made-up.example.net   not an open destination 1}]"; got != want {
		t.Errorf("refusals = %s, want %s", got, want)
	}
}
