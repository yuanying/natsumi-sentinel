package audit_test

import (
	"context"
	"testing"
	"time"

	"github.com/yuanying/natsumi-sentinel/internal/audit"
)

func TestThePrunerDeletesOnStartAndOnEveryTickWithTheRetentionInUseThen(t *testing.T) {
	l, _, _ := openLog(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	now := time.Now()
	old := &audit.Record{Time: now.Add(-48 * time.Hour), Kind: audit.KindDNS}
	if err := l.Write(ctx, old); err != nil {
		t.Fatal(err)
	}
	results := make(chan int64, 4)
	go audit.RunPruner(ctx, l, 10*time.Millisecond, func() time.Duration { return 24 * time.Hour },
		func(n int64, err error) {
			if err != nil {
				t.Errorf("prune: %v", err)
			}
			results <- n
		})
	select {
	case n := <-results:
		if n != 1 {
			t.Errorf("the first prune deleted %d, want 1", n)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the pruner did not run")
	}
	if _, err := l.Get(ctx, old.ID); err == nil {
		t.Error("the old record is still there")
	}
	select {
	case <-results:
	case <-time.After(5 * time.Second):
		t.Fatal("the pruner did not run again")
	}
}
