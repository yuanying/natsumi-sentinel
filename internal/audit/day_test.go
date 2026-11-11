package audit_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/yuanying/natsumi-sentinel/internal/audit"
)

func TestADaysWritesAsksDenialsAndAnswersAreCountedFromTheRecords(t *testing.T) {
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
	op := func(rec audit.Record, operation, target string) audit.Record {
		rec.Operation, rec.Target = operation, target
		return rec
	}
	// In the day.
	write(time.Minute, op(http("api.example.com", "POST", "/repos/o/r/issues", audit.Allow, ""), "issues.create", "owner=o repo=r"))
	write(2*time.Minute, op(http("api.example.com", "POST", "/repos/o/r/issues/1/comments", audit.Allow, ""), "issues.comment", "owner=o repo=r"))
	write(3*time.Minute, op(http("api.example.com", "POST", "/repos/o/r/issues/2/comments", audit.Allow, ""), "issues.comment", "owner=o repo=r"))
	write(4*time.Minute, http("api.example.com", "PATCH", "/repos/o/r/issues/1", audit.Allow, ""))
	write(5*time.Minute, http("cluster.example.com", "POST", "/api/v1/namespaces/a/pods", audit.Allow, ""))
	write(6*time.Minute, op(http("api.example.com", "GET", "/repos/o/r", audit.Allow, ""), "read", ""))
	write(7*time.Minute, op(http("api.example.com", "PUT", "/repos/o/r/pulls/5/merge", audit.Ask, "held as ap-1"), "pulls.merge", "owner=o repo=r"))
	write(8*time.Minute, op(http("api.example.com", "PUT", "/repos/o/r/pulls/5/merge", audit.Ask, "held as ap-1"), "pulls.merge", "owner=o repo=r"))
	write(9*time.Minute, audit.Record{Kind: audit.KindAgent, Name: "api.example.com", Method: "POST", Path: "/v1/approvals", Operation: "pulls.merge", Target: "owner=o repo=r", Verdict: audit.Ask, Approval: "ap-2", Reason: "the workspace asked beforehand"})
	write(10*time.Minute, http("api.example.com", "DELETE", "/repos/o/r", audit.Deny, "the destination's default is deny"))
	write(11*time.Minute, http("api.example.com", "DELETE", "/repos/o/r", audit.Deny, "the destination's default is deny"))
	write(12*time.Minute, audit.Record{Kind: audit.KindDNS, Name: "made-up.example.net", Verdict: audit.Deny, Reason: "not an open destination"})
	write(13*time.Minute, audit.Record{Kind: audit.KindConfig, Verdict: audit.Deny, Reason: "the routing table was not taken"})
	write(14*time.Minute, audit.Record{Kind: audit.KindGate, Name: "alerts.example.com", Method: "POST", Path: "/api/v2/alerts", Verdict: audit.Allow})
	write(15*time.Minute, audit.Record{Source: "workspace", Kind: audit.KindAnswer, Name: "api.example.com", Method: "PUT", Path: "/repos/o/r/pulls/5/merge", Operation: "pulls.merge", Target: "owner=o repo=r", Verdict: audit.Allow, Approval: "ap-1", Grant: "gr-1", Reason: "the owner allowed ap-1 with the choice 1h"})
	write(16*time.Minute, audit.Record{Source: "workspace", Kind: audit.KindAnswer, Name: "api.example.com", Operation: "pulls.merge", Target: "owner=o repo=r", Verdict: audit.Deny, Approval: "ap-1", Grant: "gr-1", Reason: "the owner revoked gr-1"})
	// Outside it.
	write(-time.Minute, http("api.example.com", "POST", "/repos/o/r/issues", audit.Allow, ""))
	write(24*time.Hour, http("api.example.com", "DELETE", "/repos/o/r", audit.Deny, "x"))

	day, err := l.Day(ctx, at, at.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	// A write with an operation is counted by its operation, whatever its
	// path; a raw one by its method.
	if got, want := fmt.Sprint(day.Writes), "[{api.example.com issues.comment  2} {api.example.com  PATCH 1} {api.example.com issues.create  1} {cluster.example.com  POST 1}]"; got != want {
		t.Errorf("writes = %s, want %s", got, want)
	}
	// What has an operation is told by it and its target; what has none by
	// its method and path.
	if got, want := fmt.Sprint(day.Asks), "[{ask http api.example.com pulls.merge owner=o repo=r   held as ap-1 2} {ask agent api.example.com pulls.merge owner=o repo=r   the workspace asked beforehand 1}]"; got != want {
		t.Errorf("asks = %s, want %s", got, want)
	}
	if got, want := fmt.Sprint(day.Denials), "[{deny http api.example.com   DELETE /repos/o/r the destination's default is deny 2} {deny dns made-up.example.net     not an open destination 1}]"; got != want {
		t.Errorf("denials = %s, want %s", got, want)
	}
	if len(day.Answers) != 2 {
		t.Fatalf("answers = %+v, want the two", day.Answers)
	}
	first, second := day.Answers[0], day.Answers[1]
	if !first.Time.Equal(at.Add(15*time.Minute)) || first.Verdict != audit.Allow || first.Approval != "ap-1" || first.Grant != "gr-1" ||
		first.Operation != "pulls.merge" || first.Target != "owner=o repo=r" || first.Source != "workspace" || first.Reason != "the owner allowed ap-1 with the choice 1h" {
		t.Errorf("the first answer = %+v", first)
	}
	if second.Verdict != audit.Deny || second.Grant != "gr-1" {
		t.Errorf("the second answer = %+v", second)
	}
}
