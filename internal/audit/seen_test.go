package audit_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/yuanying/natsumi-sentinel/internal/audit"
)

func TestAPairIsNewOnlyTheFirstTimeItIsSeen(t *testing.T) {
	l, _, _ := openLog(t)
	ctx := context.Background()
	isNew, err := l.MarkSeen(ctx, audit.Seen{Pair: "destination", Key: "api.example.com", First: at, Record: 3})
	if err != nil || !isNew {
		t.Fatalf("MarkSeen the first time = %v, %v; want new", isNew, err)
	}
	isNew, err = l.MarkSeen(ctx, audit.Seen{Pair: "destination", Key: "api.example.com", First: at.Add(time.Hour), Record: 9})
	if err != nil || isNew {
		t.Fatalf("MarkSeen again = %v, %v; want not new", isNew, err)
	}
	// The same key in another pair is another pair.
	isNew, err = l.MarkSeen(ctx, audit.Seen{Pair: "denied-name", Key: "api.example.com", First: at, Record: 4})
	if err != nil || !isNew {
		t.Fatalf("MarkSeen in another pair = %v, %v; want new", isNew, err)
	}
}

func TestWhatWasSeenOutlastsTheRecordsAndTheProcess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	l, err := audit.Open(path, &discard{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := l.MarkSeen(ctx, audit.Seen{Pair: "destination", Key: "api.example.com", First: at, Record: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Prune(ctx, at.Add(1000*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	_ = l.Close()

	l, err = audit.Open(path, &discard{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	isNew, err := l.MarkSeen(ctx, audit.Seen{Pair: "destination", Key: "api.example.com", First: at.Add(48 * time.Hour), Record: 2})
	if err != nil || isNew {
		t.Errorf("MarkSeen after pruning and reopening = %v, %v; want not new", isNew, err)
	}
}

func TestThePairsFirstSeenInAPeriodAreListedInOrder(t *testing.T) {
	l, _, _ := openLog(t)
	ctx := context.Background()
	for i, s := range []audit.Seen{
		{Pair: "destination", Key: "before.example.com", First: at.Add(-time.Hour)},
		{Pair: "write", Key: "api.example.com POST /b", First: at.Add(2 * time.Hour)},
		{Pair: "destination", Key: "api.example.com", First: at},
		{Pair: "destination", Key: "after.example.com", First: at.Add(24 * time.Hour)},
	} {
		s.Record = int64(i + 1)
		if _, err := l.MarkSeen(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	got, err := l.SeenBetween(ctx, at, at.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Key != "api.example.com" || got[1].Key != "api.example.com POST /b" {
		t.Fatalf("SeenBetween = %+v, want the two first seen in the period, oldest first", got)
	}
	if !got[0].First.Equal(at) || got[0].Record != 3 || got[0].Pair != "destination" {
		t.Errorf("SeenBetween[0] = %+v", got[0])
	}
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }
