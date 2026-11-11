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

// waitForSocket waits until authd takes connections on its socket. The
// socket's file appears when it is bound, a moment before it is listened on:
// a connection in between is refused, so the file alone is not enough.
func waitForSocket(t *testing.T, socket string, stderr *syncBuffer) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := net.Dial("unix", socket)
		if err == nil {
			_ = c.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the socket did not take a connection: %v; stderr: %s", err, stderr.String())
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

	waitForSocket(t, socket, stderr)

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
	_, err := tr.RoundTrip(req)
	var aerr *authdclient.Error
	if !errors.As(err, &aerr) || aerr.Reason != authdclient.ReasonUpstreamNotRegistered {
		t.Fatalf("RoundTrip = %v, want authd to refuse an unregistered upstream", err)
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

const (
	testSurrogate = "surrogate-0123456789abcdef"
	testKey       = "real-key-for-the-test-only"
)

// withCredential rewrites the registration at config with a second upstream
// and one credential whose key is at keyFile, which need not exist.
func withCredential(t *testing.T, config, keyFile, caFile string) {
	t.Helper()
	text := "upstreams:\n  - name: api.example.com\n"
	if caFile != "" {
		text += "    ca_file: " + caFile + "\n"
	}
	text += "credentials:\n  - surrogate: " + testSurrogate + "\n    key_file: " + keyFile + "\n    upstreams: [api.example.com]\n    places:\n      - type: bearer\n"
	if err := os.WriteFile(config, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

// startAuthd runs authd with the metrics on until the test ends, and
// returns the metrics' address.
func startAuthd(t *testing.T, config, socket string) (net.Addr, *syncBuffer) {
	t.Helper()
	addrs := make(chan net.Addr, 1)
	old := onMetricsListen
	onMetricsListen = func(a net.Addr) { addrs <- a }
	t.Cleanup(func() { onMetricsListen = old })

	ctx, cancel := context.WithCancel(context.Background())
	stderr := &syncBuffer{}
	done := make(chan int, 1)
	go func() {
		done <- run(ctx, []string{"--config", config, "--socket", socket, "--peer-uid", strconv.Itoa(os.Getuid()), "--metrics-listen", "127.0.0.1:0"}, &bytes.Buffer{}, stderr)
	}()
	t.Cleanup(func() { cancel(); <-done })
	var addr net.Addr
	select {
	case addr = <-addrs:
	case code := <-done:
		done <- code
		t.Fatalf("run = %d before listening; stderr: %s", code, stderr.String())
	case <-time.After(5 * time.Second):
		t.Fatal("the metrics were not listened for")
	}
	waitForSocket(t, socket, stderr)
	return addr, stderr
}

func metricsPage(t *testing.T, addr net.Addr) string {
	t.Helper()
	resp, err := http.Get("http://" + addr.String() + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

func TestAKeyFileThatCannotBeReadAtTheStartDoesNotStopTheStart(t *testing.T) {
	config, socket := setup(t)
	keyFile := filepath.Join(t.TempDir(), "missing-key")
	withCredential(t, config, keyFile, "")

	addr, stderr := startAuthd(t, config, socket)

	logs := stderr.String()
	if !strings.Contains(logs, "credentials[0]") && !strings.Contains(logs, `"credential":0`) {
		t.Errorf("the logs %q do not name the credential by its position", logs)
	}
	if !strings.Contains(logs, keyFile) {
		t.Errorf("the logs %q do not name the key file", logs)
	}
	if strings.Contains(logs, testSurrogate) {
		t.Errorf("the logs %q show the surrogate", logs)
	}
	if page := metricsPage(t, addr); !strings.Contains(page, `authd_key_read_failures_total{credential="0"} 1`) {
		t.Errorf("the metrics do not count the key that could not be read at the start:\n%s", page)
	}

	tr := authdclient.NewTransport(socket)
	defer tr.CloseIdleConnections()
	req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/", nil)
	req.Header.Set("Authorization", "Bearer "+testSurrogate)
	_, err := tr.RoundTrip(req)
	var aerr *authdclient.Error
	if !errors.As(err, &aerr) || aerr.Reason != authdclient.ReasonCredentialUnavailable {
		t.Fatalf("RoundTrip = %v, want the request that uses the key refused as credential-unavailable", err)
	}
}
