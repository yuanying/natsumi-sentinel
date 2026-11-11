package notice_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/yuanying/natsumi-sentinel/internal/audit"
	"github.com/yuanying/natsumi-sentinel/internal/metrics"
	"github.com/yuanying/natsumi-sentinel/internal/notice"
)

var at = time.Date(2026, 11, 11, 9, 30, 0, 0, time.UTC)

func openLog(t *testing.T) *audit.Log {
	t.Helper()
	l, err := audit.Open(filepath.Join(t.TempDir(), "audit.db"), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

func page(t *testing.T, reg *prometheus.Registry) string {
	t.Helper()
	srv := httptest.NewServer(metrics.Handler(reg))
	defer srv.Close()
	resp, err := http.Get(srv.URL + metrics.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

func wantLines(t *testing.T, page string, lines ...string) {
	t.Helper()
	for _, l := range lines {
		if !strings.Contains(page, l+"\n") {
			t.Errorf("the metrics do not carry %q", l)
		}
	}
}

// fakeSender keeps what it is given, failing while fail is set.
type fakeSender struct {
	mu   sync.Mutex
	fail error
	sent [][]notice.Notice
	got  chan struct{}
}

func newFakeSender() *fakeSender { return &fakeSender{got: make(chan struct{}, 100)} }

func (f *fakeSender) Send(_ context.Context, ns []notice.Notice) error {
	f.mu.Lock()
	defer func() {
		f.mu.Unlock()
		f.got <- struct{}{}
	}()
	if f.fail != nil {
		return f.fail
	}
	f.sent = append(f.sent, append([]notice.Notice(nil), ns...))
	return nil
}

func (f *fakeSender) setFail(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fail = err
}

func (f *fakeSender) all() []notice.Notice {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []notice.Notice
	for _, b := range f.sent {
		out = append(out, b...)
	}
	return out
}

func (f *fakeSender) wait(t *testing.T) {
	t.Helper()
	select {
	case <-f.got:
	case <-time.After(5 * time.Second):
		t.Fatal("nothing was sent")
	}
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// eventually waits for ok to hold.
func eventually(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("%s did not happen", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
