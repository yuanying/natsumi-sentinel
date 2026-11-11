package metrics_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yuanying/natsumi-sentinel/internal/metrics"
)

func get(t *testing.T, h http.Handler, path string) (int, string) {
	t.Helper()
	srv := httptest.NewServer(h)
	defer srv.Close()
	resp, err := http.Get(srv.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestTheMetricsPageCarriesTheBuildInfoAndTheRuntime(t *testing.T) {
	reg := metrics.NewRegistry("sentinel", "v1.2.3")
	status, body := get(t, metrics.Handler(reg), "/metrics")
	if status != http.StatusOK {
		t.Fatalf("GET /metrics = %d, want 200", status)
	}
	for _, want := range []string{
		`sentinel_build_info{version="v1.2.3"} 1`,
		"go_goroutines",
		"process_start_time_seconds",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the page does not carry %q", want)
		}
	}
}

func TestOnlyTheMetricsPathIsServed(t *testing.T) {
	reg := metrics.NewRegistry("authd", "dev")
	if status, _ := get(t, metrics.Handler(reg), "/"); status != http.StatusNotFound {
		t.Errorf("GET / = %d, want 404", status)
	}
}

func TestServeAnswersOnTheListenerUntilTheContextIsDone(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- metrics.Serve(ctx, ln, metrics.NewRegistry("authd", "dev")) }()

	resp, err := http.Get("http://" + ln.Addr().String() + metrics.Path)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET = %d, want 200", resp.StatusCode)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Serve = %v after the context was done, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return")
	}
}
