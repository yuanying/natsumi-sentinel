package audit_test

import (
	"bytes"
	"context"
	"encoding/json"
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
