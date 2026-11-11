package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yuanying/natsumi-sentinel/internal/authdclient"
)

// waitForSocket waits for authd's socket to appear.
func waitForSocket(t *testing.T, socket string, stderr *syncBuffer) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(socket); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the socket did not appear; stderr: %s", stderr.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestVersionFlagPrintsTheVersionAndSucceeds(t *testing.T) {
	old := version
	version = "v1.2.3"
	t.Cleanup(func() { version = old })

	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"--version"}, &stdout, &stderr); code != 0 {
		t.Fatalf("run(--version) = %d, want 0; stderr: %s", code, stderr.String())
	}
	if got, want := stdout.String(), "authd v1.2.3\n"; got != want {
		t.Errorf("stdout = %q, want %q", got, want)
	}
}

func TestAnUnknownFlagIsAUsageError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"--no-such-flag"}, &stdout, &stderr); code != 2 {
		t.Fatalf("run(--no-such-flag) = %d, want 2", code)
	}
}

// dirs gives a registration with one upstream and no credentials, and a
// socket path short enough for a Unix socket.
func setup(t *testing.T) (config, socket string) {
	t.Helper()
	dir := t.TempDir()
	config = filepath.Join(dir, "authd.yaml")
	if err := os.WriteFile(config, []byte("upstreams:\n  - name: api.example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sockDir, err := os.MkdirTemp("", "authd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	return config, filepath.Join(sockDir, "authd.sock")
}

func TestEachRequiredFlagMissingIsAUsageError(t *testing.T) {
	config, socket := setup(t)
	uid := strconv.Itoa(os.Getuid())
	all := map[string]string{"--config": config, "--socket": socket, "--peer-uid": uid}
	for missing := range all {
		var args []string
		for f, v := range all {
			if f != missing {
				args = append(args, f, v)
			}
		}
		var stdout, stderr bytes.Buffer
		if code := run(context.Background(), args, &stdout, &stderr); code != 2 {
			t.Errorf("without %s: run = %d, want 2", missing, code)
		}
		if !strings.Contains(stderr.String(), strings.TrimPrefix(missing, "--")) {
			t.Errorf("without %s: stderr %q does not name it", missing, stderr.String())
		}
	}
}

func TestARegistrationThatCannotBeReadStopsTheStartWithoutASocket(t *testing.T) {
	config, socket := setup(t)
	if err := os.WriteFile(config, []byte("upstreams: ["), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"--config", config, "--socket", socket, "--peer-uid", strconv.Itoa(os.Getuid())}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run = %d, want 1", code)
	}
	if _, err := os.Stat(socket); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the socket exists: %v", err)
	}
	if !strings.Contains(stderr.String(), "registration") {
		t.Errorf("stderr %q does not say the registration is the trouble", stderr.String())
	}
}

func TestItServesOnTheSocketUntilItIsToldToStop(t *testing.T) {
	config, socket := setup(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stderr := &syncBuffer{}
	done := make(chan int, 1)
	go func() {
		done <- run(ctx, []string{"--config", config, "--socket", socket, "--peer-uid", strconv.Itoa(os.Getuid())}, &bytes.Buffer{}, stderr)
	}()

	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(socket); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the socket did not appear; stderr: %s", stderr.String())
		}
		time.Sleep(10 * time.Millisecond)
	}

	tr := authdclient.NewTransport(socket)
	defer tr.CloseIdleConnections()
	req, _ := http.NewRequest(http.MethodGet, "https://nowhere.example.com/", nil)
	_, err := tr.RoundTrip(req)
	var aerr *authdclient.Error
	if !errors.As(err, &aerr) || aerr.Reason != authdclient.ReasonUpstreamNotRegistered {
		t.Fatalf("RoundTrip = %v, want authd to refuse an unregistered upstream", err)
	}

	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Errorf("run = %d after being told to stop, want 0; stderr: %s", code, stderr.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not return after being told to stop")
	}
}

func TestTheMetricsCountRefusalsByReason(t *testing.T) {
	config, socket := setup(t)
	addrs := make(chan net.Addr, 1)
	old := onMetricsListen
	onMetricsListen = func(a net.Addr) { addrs <- a }
	t.Cleanup(func() { onMetricsListen = old })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stderr := &syncBuffer{}
	done := make(chan int, 1)
	go func() {
		done <- run(ctx, []string{"--config", config, "--socket", socket, "--peer-uid", strconv.Itoa(os.Getuid()), "--metrics-listen", "127.0.0.1:0"}, &bytes.Buffer{}, stderr)
	}()
	var addr net.Addr
	select {
	case addr = <-addrs:
	case code := <-done:
		t.Fatalf("run = %d before listening; stderr: %s", code, stderr.String())
	case <-time.After(5 * time.Second):
		t.Fatal("the metrics were not listened for")
	}
	waitForSocket(t, socket, stderr)

	tr := authdclient.NewTransport(socket)
	defer tr.CloseIdleConnections()
	req, _ := http.NewRequest(http.MethodGet, "https://nowhere.example.com/", nil)
	if _, err := tr.RoundTrip(req); err == nil {
		t.Fatal("an unregistered upstream was not refused")
	}

	resp, err := http.Get("http://" + addr.String() + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	page := string(b)
	for _, want := range []string{
		`authd_refusals_total{reason="upstream-not-registered"} 1`,
		`authd_refusals_total{reason="surrogate-mismatch"} 0`,
		`authd_upstream_failures_total{reason="upstream-unreachable"} 0`,
		`authd_build_info{version="dev"} 1`,
		"authd_refused_peers_total 0",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the metrics do not carry %q", want)
		}
	}
	cancel()
	<-done
}

func TestAMetricsAddressThatCannotBeListenedOnStopsTheStart(t *testing.T) {
	config, socket := setup(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	var stderr bytes.Buffer
	code := run(context.Background(), []string{"--config", config, "--socket", socket, "--peer-uid", strconv.Itoa(os.Getuid()), "--metrics-listen", ln.Addr().String()}, &bytes.Buffer{}, &stderr)
	if code != 1 {
		t.Fatalf("run = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "metrics") {
		t.Errorf("stderr %q does not say the metrics are the trouble", stderr.String())
	}
}
