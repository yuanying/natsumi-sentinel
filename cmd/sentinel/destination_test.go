package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestDestinationGrantsNeedAuthdsRegistration(t *testing.T) {
	s := newSetup(t)
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), s.args("-destination-grants"), &stdout, &stderr); code != 2 {
		t.Fatalf("run = %d, want 2; stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "-authd-registration") {
		t.Errorf("stderr %q does not name -authd-registration", stderr.String())
	}
}

// serve runs the gate with args until the test ends, and gives where it
// listens.
func serve(t *testing.T, s setup, extra ...string) map[string]net.Addr {
	t.Helper()
	withUpstream(t)
	l := &listened{addrs: map[string]net.Addr{}, ready: make(chan struct{})}
	old := onListen
	onListen = func(source, what string, addr net.Addr) {
		l.mu.Lock()
		defer l.mu.Unlock()
		l.addrs[source+"/"+what] = addr
		if len(l.addrs) == 4 {
			close(l.ready)
		}
	}
	t.Cleanup(func() { onListen = old })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	var stdout, stderr syncBuffer
	go func() { done <- run(ctx, s.args(extra...), &stdout, &stderr) }()
	var once sync.Once
	t.Cleanup(func() {
		once.Do(cancel)
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("it did not stop")
		}
	})
	select {
	case <-l.ready:
	case code := <-done:
		t.Fatalf("run returned %d before listening; stderr: %s", code, stderr.String())
	case <-time.After(10 * time.Second):
		t.Fatal("it did not listen")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.addrs
}

func ask(t *testing.T, addr net.Addr, name string) dnsmessage.RCode {
	t.Helper()
	c, err := net.Dial("udp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 7})
	_ = b.StartQuestions()
	_ = b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	q, _ := b.Finish()
	if _, err := c.Write(q); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 512)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("no answer: %v", err)
	}
	var m dnsmessage.Message
	if err := m.Unpack(buf[:n]); err != nil {
		t.Fatal(err)
	}
	return m.RCode
}

func ownerGet(t *testing.T, s setup, path string) (int, map[string]any) {
	t.Helper()
	oc := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", s.approvals)
	}}, Timeout: 5 * time.Second}
	resp, err := oc.Get("http://sentinel" + path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	out := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func registration(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "registration.yaml")
	if err := os.WriteFile(path, []byte("credentials:\n  - surrogate: surrogate-0123456789abcdef\n    key_file: /never/read\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestWithDestinationGrantsARefusedNameIsOnTheOwnersList(t *testing.T) {
	s := newSetup(t)
	addrs := serve(t, s, "-destination-grants", "-authd-registration", registration(t))
	if rc := ask(t, addrs["workspace/dns-udp"], "new.example.net."); rc != dnsmessage.RCodeNameError {
		t.Fatalf("rcode = %v", rc)
	}
	code, out := ownerGet(t, s, "/v1/refused-names")
	if code != http.StatusOK {
		t.Fatalf("code = %d", code)
	}
	names, _ := out["names"].([]any)
	if len(names) != 1 || names[0].(map[string]any)["name"] != "new.example.net" {
		t.Errorf("names = %v", out)
	}
}

func TestWithoutDestinationGrantsNoNameIsRememberedAndTheListIsNotThere(t *testing.T) {
	s := newSetup(t)
	addrs := serve(t, s)
	if rc := ask(t, addrs["workspace/dns-udp"], "new.example.net."); rc != dnsmessage.RCodeNameError {
		t.Fatalf("rcode = %v", rc)
	}
	if code, _ := ownerGet(t, s, "/v1/refused-names"); code != http.StatusNotFound {
		t.Errorf("code = %d", code)
	}
}
