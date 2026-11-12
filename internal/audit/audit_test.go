package audit_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yuanying/natsumi-sentinel/internal/audit"
)

func openLog(t *testing.T) (*audit.Log, *bytes.Buffer, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.db")
	var out bytes.Buffer
	l, err := audit.Open(path, &out)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l, &out, path
}

var at = time.Date(2026, 11, 11, 9, 30, 0, 123456789, time.UTC)

func TestARecordIsKeptInSQLiteAndCopiedToOneLineOfJSON(t *testing.T) {
	l, out, _ := openLog(t)
	ctx := context.Background()
	rec := &audit.Record{
		Time:      at,
		Source:    "workspace",
		Kind:      audit.KindDNS,
		Name:      "unknown.example.com",
		Verdict:   audit.Deny,
		Reason:    "not in the routing table",
		DNSType:   "A",
		DNSRcode:  "NXDOMAIN",
		DNSAnswer: []string{},
	}
	if err := l.Write(ctx, rec); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if rec.ID == 0 {
		t.Fatal("Write did not give the record an id")
	}

	got, err := l.Get(ctx, rec.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Name != rec.Name || got.Verdict != audit.Deny || got.DNSRcode != "NXDOMAIN" || !got.Time.Equal(at) || !got.Finished {
		t.Errorf("Get = %+v, want what was written", got)
	}

	lines := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
	if len(lines) != 1 {
		t.Fatalf("stdout has %d lines, want 1: %q", len(lines), out.String())
	}
	var copied audit.Record
	if err := json.Unmarshal([]byte(lines[0]), &copied); err != nil {
		t.Fatalf("the line is not JSON: %v", err)
	}
	if copied.ID != rec.ID || copied.Name != rec.Name || copied.Kind != audit.KindDNS {
		t.Errorf("the line = %+v, want the same record", copied)
	}
}

func TestARecordBegunBeforeSendingIsFinishedWithWhatCameBack(t *testing.T) {
	l, out, _ := openLog(t)
	ctx := context.Background()
	rec := &audit.Record{
		Time:      at,
		Source:    "workspace",
		Kind:      audit.KindHTTP,
		Treatment: "open",
		Name:      "api.example.com",
		Address:   "192.0.2.1:443",
		Method:    "POST",
		Path:      "/repos/o/r/issues",
		Query:     "a=b",
		Verdict:   audit.Allow,
		Reason:    "the destination's default",
		Request:   &audit.Body{Text: `{"title":"x"}`, Size: 13},
	}
	if err := l.Begin(ctx, rec); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if out.Len() != 0 {
		t.Errorf("Begin wrote %q to stdout; the copy is written when the record is finished", out.String())
	}
	began, err := l.Get(ctx, rec.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if began.Finished || began.Request == nil || began.Request.Text != `{"title":"x"}` {
		t.Errorf("after Begin, Get = %+v; want the body and not finished", began)
	}

	rec.Status = 201
	rec.ResponseBytes = 42
	rec.Duration = 1500 * time.Millisecond
	rec.Request.SHA256 = "abc"
	if err := l.Finish(ctx, rec); err != nil {
		t.Fatalf("Finish: %v", err)
	}
	got, err := l.Get(ctx, rec.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !got.Finished || got.Status != 201 || got.ResponseBytes != 42 || got.Duration != 1500*time.Millisecond || got.Request.SHA256 != "abc" || got.Query != "a=b" {
		t.Errorf("after Finish, Get = %+v", got)
	}
	if !strings.Contains(out.String(), `"status":201`) {
		t.Errorf("stdout = %q, want the finished record", out.String())
	}
}

func TestARecordThatCannotBeWrittenIsAnError(t *testing.T) {
	l, _, _ := openLog(t)
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if err := l.Write(context.Background(), &audit.Record{Time: at, Kind: audit.KindDNS}); err == nil {
		t.Fatal("Write returned no error on a closed log")
	}
	if err := l.Begin(context.Background(), &audit.Record{Time: at, Kind: audit.KindHTTP}); err == nil {
		t.Fatal("Begin returned no error on a closed log")
	}
}

func TestRecordsOlderThanTheRetentionAreDeleted(t *testing.T) {
	l, _, _ := openLog(t)
	ctx := context.Background()
	old := &audit.Record{Time: at.Add(-91 * 24 * time.Hour), Kind: audit.KindDNS}
	recent := &audit.Record{Time: at.Add(-89 * 24 * time.Hour), Kind: audit.KindDNS}
	for _, r := range []*audit.Record{old, recent} {
		if err := l.Write(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	n, err := l.Prune(ctx, at.Add(-90*24*time.Hour))
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if n != 1 {
		t.Errorf("Prune deleted %d, want 1", n)
	}
	if _, err := l.Get(ctx, old.ID); err == nil {
		t.Error("the old record is still there")
	}
	if _, err := l.Get(ctx, recent.ID); err != nil {
		t.Errorf("the recent record is gone: %v", err)
	}
}

func TestALogIsOpenedAgainWithItsRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	ctx := context.Background()
	l, err := audit.Open(path, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	rec := &audit.Record{Time: at, Kind: audit.KindDNS, Name: "a.example.com"}
	if err := l.Write(ctx, rec); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	l, err = audit.Open(path, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("Open again: %v", err)
	}
	defer func() { _ = l.Close() }()
	if got, err := l.Get(ctx, rec.ID); err != nil || got.Name != "a.example.com" {
		t.Errorf("Get after reopening = %+v, %v", got, err)
	}
}

func TestALogInADirectoryThatDoesNotExistDoesNotOpen(t *testing.T) {
	if _, err := audit.Open(filepath.Join(t.TempDir(), "missing", "audit.db"), &bytes.Buffer{}); err == nil {
		t.Fatal("Open returned no error")
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, bytes.ErrTooLarge }

func TestAStdoutThatFailsDoesNotLoseTheRecord(t *testing.T) {
	l, err := audit.Open(filepath.Join(t.TempDir(), "audit.db"), failingWriter{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	rec := &audit.Record{Time: at, Kind: audit.KindDNS}
	if err := l.Write(context.Background(), rec); err != nil {
		t.Fatalf("Write: %v; the SQLite record is the one that counts", err)
	}
	if _, err := l.Get(context.Background(), rec.ID); err != nil {
		t.Errorf("Get: %v", err)
	}
}

func TestTheFieldsOfDecisionsAndAuthdAreKeptAndReadBack(t *testing.T) {
	l, out, _ := openLog(t)
	ctx := context.Background()
	rec := &audit.Record{
		Time:        at,
		Kind:        audit.KindHTTP,
		Verdict:     audit.Ask,
		Operation:   "pulls.merge",
		Target:      "owner=o repo=r",
		Approval:    "ap-1",
		Grant:       "gr-1",
		AuthdReason: "surrogate-mismatch",
	}
	if err := l.Write(ctx, rec); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got, err := l.Get(ctx, rec.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Verdict != audit.Ask || got.Operation != rec.Operation || got.Target != rec.Target ||
		got.Approval != rec.Approval || got.Grant != rec.Grant || got.AuthdReason != rec.AuthdReason {
		t.Errorf("Get = %+v", got)
	}
	for _, field := range []string{`"operation":"pulls.merge"`, `"target":"owner=o repo=r"`, `"approval":"ap-1"`, `"grant":"gr-1"`, `"authdReason":"surrogate-mismatch"`} {
		if !strings.Contains(out.String(), field) {
			t.Errorf("stdout = %s, want %s", out.String(), field)
		}
	}
}

func TestALogOfTheFirstVersionIsMovedToTheCurrentOneWithItsRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{audit.SchemaV1ForTest, "PRAGMA user_version = 1",
		`INSERT INTO records (time, source, kind, treatment, name, address, method, path, query, verdict, reason,
			status, response_bytes, bytes_up, bytes_down, duration_ns, dns_type, dns_rcode, dns_answer, error, finished)
			VALUES ('2026-11-11T00:00:00.000000000Z', 'workspace', 'dns', '', 'old.example.com', '', '', '', '', 'deny', 'r',
			0, 0, 0, 0, 0, 'A', 'NXDOMAIN', '[]', '', 1)`} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	_ = db.Close()

	l, err := audit.Open(path, io.Discard)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = l.Close() }()
	got, err := l.Get(context.Background(), 1)
	if err != nil || got.Name != "old.example.com" || got.Operation != "" {
		t.Fatalf("Get = %+v, %v", got, err)
	}
	rec := &audit.Record{Time: at, Kind: audit.KindHTTP, Operation: "op"}
	if err := l.Write(context.Background(), rec); err != nil {
		t.Fatalf("Write after the move: %v", err)
	}
}

func TestRecordsAreListedNewestFirstAndCanBeNarrowedAndPaged(t *testing.T) {
	l, _, _ := openLog(t)
	ctx := context.Background()
	for i, r := range []audit.Record{
		{Source: "workspace", Kind: audit.KindHTTP, Verdict: audit.Allow, Name: "a"},
		{Source: "workspace", Kind: audit.KindHTTP, Verdict: audit.Deny, Name: "b"},
		{Source: "other", Kind: audit.KindHTTP, Verdict: audit.Deny, Name: "c"},
		{Source: "workspace", Kind: audit.KindDNS, Verdict: audit.Deny, Name: "d"},
		{Source: "workspace", Kind: audit.KindHTTP, Verdict: audit.Ask, Name: "e"},
	} {
		r.Time = at.Add(time.Duration(i) * time.Second)
		if err := l.Write(ctx, &r); err != nil {
			t.Fatal(err)
		}
	}
	names := func(q audit.Query) string {
		t.Helper()
		recs, err := l.List(ctx, q)
		if err != nil {
			t.Fatal(err)
		}
		var s []string
		for _, r := range recs {
			s = append(s, r.Name)
		}
		return strings.Join(s, ",")
	}
	for q, want := range map[*audit.Query]string{
		{}:                     "e,d,c,b,a",
		{Limit: 2}:             "e,d",
		{Before: 4, Limit: 2}:  "c,b",
		{Kind: audit.KindHTTP}: "e,c,b,a",
		{Source: "workspace", Kind: audit.KindHTTP, Verdicts: []audit.Verdict{audit.Deny, audit.Ask}}: "e,b",
		{Since: at.Add(3 * time.Second)}: "e,d",
	} {
		if got := names(*q); got != want {
			t.Errorf("List(%+v) = %s, want %s", *q, got, want)
		}
	}
}

func TestMovingALogOfTheFirstVersionKeepsThePairsSeen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	l, err := audit.Open(path, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.MarkSeen(context.Background(), audit.Seen{Pair: "destination", Key: "api.example.com", First: at, Record: 1}); err != nil {
		t.Fatal(err)
	}
	_ = l.Close()
	// Make it a file of the first version, as a gate before this one left
	// it: its records table and user_version, with the pairs seen beside.
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{"DROP TABLE records", audit.SchemaV1ForTest, "PRAGMA user_version = 1"} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	_ = db.Close()

	l, err = audit.Open(path, io.Discard)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = l.Close() }()
	isNew, err := l.MarkSeen(context.Background(), audit.Seen{Pair: "destination", Key: "api.example.com", First: at, Record: 2})
	if err != nil || isNew {
		t.Errorf("MarkSeen after the move = %v, %v; want the pair still known", isNew, err)
	}
	if err := l.Write(context.Background(), &audit.Record{Time: at, Kind: audit.KindHTTP, Operation: "op"}); err != nil {
		t.Errorf("Write after the move: %v", err)
	}
}

func TestThatARequestWasAReadIsKeptAndReadBack(t *testing.T) {
	l, out, _ := openLog(t)
	ctx := context.Background()
	rec := &audit.Record{Time: at, Kind: audit.KindHTTP, Method: "POST", Path: "/o/r.git/git-upload-pack", Verdict: audit.Allow, Read: true}
	if err := l.Begin(ctx, rec); err != nil {
		t.Fatal(err)
	}
	if err := l.Finish(ctx, rec); err != nil {
		t.Fatal(err)
	}
	got, err := l.Get(ctx, rec.ID)
	if err != nil || !got.Read {
		t.Fatalf("Get = %+v, %v; want a read", got, err)
	}
	if !strings.Contains(out.String(), `"read":true`) {
		t.Errorf("stdout = %s, want the read", out.String())
	}
	recs, err := l.List(ctx, audit.Query{})
	if err != nil || len(recs) != 1 || !recs[0].Read {
		t.Errorf("List = %+v, %v", recs, err)
	}
}

func TestMovingALogOfAnEarlierVersionMarksItsReadsByMethod(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	insert := func(kind, method string) string {
		return `INSERT INTO records (time, source, kind, treatment, name, address, method, path, query, verdict, reason,
			status, response_bytes, bytes_up, bytes_down, duration_ns, dns_type, dns_rcode, dns_answer, error, finished)
			VALUES ('2026-11-11T00:00:00.000000000Z', 'workspace', '` + kind + `', 'open', 'api.example.com', '', '` + method + `', '/', '', 'allow', '',
			0, 0, 0, 0, 0, '', '', '[]', '', 1)`
	}
	for _, stmt := range []string{audit.SchemaV1ForTest, "PRAGMA user_version = 1",
		insert("http", "GET"), insert("http", "POST"), insert("http", "HEAD"), insert("connection", "GET")} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	_ = db.Close()

	l, err := audit.Open(path, io.Discard)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = l.Close() }()
	for id, want := range map[int64]bool{1: true, 2: false, 3: true, 4: false} {
		got, err := l.Get(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		if got.Read != want {
			t.Errorf("record %d (%s %s): read = %v, want %v", id, got.Kind, got.Method, got.Read, want)
		}
	}
}
