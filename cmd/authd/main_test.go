package main

import (
	"bytes"
	"context"
	"errors"
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
