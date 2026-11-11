package main

import (
	"bytes"
	"context"
	"database/sql"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/yuanying/natsumi-sentinel/internal/authdclient"
	"github.com/yuanying/natsumi-sentinel/internal/testca"
)

func TestVersionFlagPrintsTheVersionAndSucceeds(t *testing.T) {
	old := version
	version = "v1.2.3"
	t.Cleanup(func() { version = old })

	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"--version"}, &stdout, &stderr); code != 0 {
		t.Fatalf("run(--version) = %d, want 0; stderr: %s", code, stderr.String())
	}
	if got, want := stdout.String(), "sentinel v1.2.3\n"; got != want {
		t.Errorf("stdout = %q, want %q", got, want)
	}
}

func TestAnUnknownFlagIsAUsageError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"--no-such-flag"}, &stdout, &stderr); code != 2 {
		t.Fatalf("run(--no-such-flag) = %d, want 2", code)
	}
}

const routesYAML = `
destinations:
  - name: api.example.com
    treatment: open
    default: allow
`

type setup struct {
	config, db, authd, ledger, approvals string
	ca                                   *testca.CA
}

func newSetup(t *testing.T) setup {
	t.Helper()
	config := t.TempDir()
	if err := os.WriteFile(filepath.Join(config, "routes.yaml"), []byte(routesYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	// Unix socket paths have to be short.
	sockDir, err := os.MkdirTemp("", "sentinel")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	data := t.TempDir()
	return setup{
		config: config, db: filepath.Join(data, "audit.db"), ledger: filepath.Join(data, "ledger.db"),
		authd: filepath.Join(sockDir, "authd.sock"), approvals: filepath.Join(sockDir, "approvals.sock"),
		ca: testca.New(t),
	}
}

func (s setup) args(extra ...string) []string {
	return append([]string{
		"-config", s.config,
		"-ca-cert", s.ca.CertFile,
		"-ca-key", s.ca.KeyFile,
		"-db", s.db,
		"-authd-socket", s.authd,
		"-ledger", s.ledger,
		"-approvals-socket", s.approvals,
		"-approvals-peer-uid", strconv.Itoa(os.Getuid()),
		"-source", "name=workspace,proxy=127.0.0.1:0,dns=127.0.0.1:0",
	}, extra...)
}

func TestWithoutTheRoutingDirectoryItIsAUsageError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), nil, &stdout, &stderr); code != 2 {
		t.Fatalf("run() = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "-config") {
		t.Errorf("stderr = %q, want it to name -config", stderr.String())
	}
}

func TestCheckSaysWhetherTheRoutingTableCanBeUsed(t *testing.T) {
	s := newSetup(t)
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"-check", "-config", s.config}, &stdout, &stderr); code != 0 {
		t.Fatalf("run(-check) = %d, want 0; stderr: %s", code, stderr.String())
	}

	if err := os.WriteFile(filepath.Join(s.config, "broken.yaml"), []byte("destinations: [::"), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run(context.Background(), []string{"-check", "-config", s.config}, &stdout, &stderr); code != 1 {
		t.Fatalf("run(-check) on a broken table = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "broken.yaml") {
		t.Errorf("stderr = %q, want it to name the broken file", stderr.String())
	}
}

func TestWithoutAnAuthdSocketItIsAUsageError(t *testing.T) {
	s := newSetup(t)
	args := []string{"-config", s.config, "-ca-cert", s.ca.CertFile, "-ca-key", s.ca.KeyFile, "-db", s.db,
		"-source", "name=workspace,proxy=127.0.0.1:0,dns=127.0.0.1:0"}
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), args, &stdout, &stderr); code != 2 {
		t.Fatalf("run = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "-authd-socket") {
		t.Errorf("stderr = %q, want it to name -authd-socket", stderr.String())
	}
}

func TestWithoutTheLedgerOrTheApprovalsSocketItIsAUsageError(t *testing.T) {
	for _, flag := range []string{"-ledger", "-approvals-socket", "-approvals-peer-uid"} {
		t.Run(flag, func(t *testing.T) {
			s := newSetup(t)
			args := s.args()
			for i, a := range args {
				if a == flag {
					args = append(args[:i:i], args[i+2:]...)
					break
				}
			}
			var stdout, stderr bytes.Buffer
			if code := run(context.Background(), args, &stdout, &stderr); code != 2 {
				t.Fatalf("run = %d, want 2", code)
			}
			if !strings.Contains(stderr.String(), flag) {
				t.Errorf("stderr = %q, want it to name %s", stderr.String(), flag)
			}
		})
	}
}

func TestTheUpstreamIsAuthdAtItsSocket(t *testing.T) {
	var got string
	old := newUpstream
	newUpstream = func(socket string) http.RoundTripper {
		got = socket
		return old(socket)
	}
	t.Cleanup(func() { newUpstream = old })
	if _, ok := old("/run/authd.sock").(*authdclient.Transport); !ok {
		t.Error("the upstream is not authdclient's Transport")
	}

	s := newSetup(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var stdout, stderr bytes.Buffer
	if code := run(ctx, s.args(), &stdout, &stderr); code != 0 {
		t.Fatalf("run = %d, want 0; stderr: %s", code, stderr.String())
	}
	if got != s.authd {
		t.Errorf("the upstream was made for %q, want %q", got, s.authd)
	}
}

func TestItDoesNotStartWithoutWhatItNeeds(t *testing.T) {
	withUpstream(t)
	tests := map[string]func(s *setup) []string{
		"a broken routing table": func(s *setup) []string {
			_ = os.WriteFile(filepath.Join(s.config, "routes.yaml"), []byte("destinations: [::"), 0o600)
			return s.args()
		},
		"a CA that cannot be read": func(s *setup) []string {
			s.ca.KeyFile = filepath.Join(t.TempDir(), "missing.key")
			return s.args()
		},
		"an audit log that cannot be opened": func(s *setup) []string {
			s.db = filepath.Join(t.TempDir(), "missing", "audit.db")
			return s.args()
		},
		"a ledger that cannot be opened": func(s *setup) []string {
			s.ledger = filepath.Join(t.TempDir(), "missing", "ledger.db")
			return s.args()
		},
		"an approvals socket that cannot be listened on": func(s *setup) []string {
			s.approvals = filepath.Join(t.TempDir(), "missing", "approvals.sock")
			return s.args()
		},
	}
	for name, mk := range tests {
		t.Run(name, func(t *testing.T) {
			s := newSetup(t)
			var stdout, stderr bytes.Buffer
			if code := run(context.Background(), mk(&s), &stdout, &stderr); code != 1 {
				t.Fatalf("run = %d, want 1; stderr: %s", code, stderr.String())
			}
		})
	}
}

func TestASourceMustBeNamedAndListenForBoth(t *testing.T) {
	for _, src := range []string{
		"proxy=:1,dns=:2",
		"name=workspace,dns=:2",
		"name=workspace,proxy=:1",
		"name=workspace,proxy=:1,dns=:2,extra=3",
		"garbage",
	} {
		t.Run(src, func(t *testing.T) {
			s := newSetup(t)
			args := []string{"-config", s.config, "-ca-cert", s.ca.CertFile, "-ca-key", s.ca.KeyFile, "-db", s.db, "-authd-socket", s.authd, "-source", src}
			var stdout, stderr bytes.Buffer
			if code := run(context.Background(), args, &stdout, &stderr); code != 2 {
				t.Fatalf("run = %d, want 2", code)
			}
		})
	}
}

// withUpstream builds an upstream sender in for one test.
func withUpstream(t *testing.T) {
	t.Helper()
	old := newUpstream
	newUpstream = func(string) http.RoundTripper { return http.DefaultTransport }
	t.Cleanup(func() { newUpstream = old })
}

type listened struct {
	mu    sync.Mutex
	addrs map[string]net.Addr
	ready chan struct{}
}

func TestWithAnUpstreamItServesTheSourceAndRecordsUntilStopped(t *testing.T) {
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

	s := newSetup(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	var stdout, stderr syncBuffer
	go func() {
		done <- run(ctx, s.args("-gate-name", "sentinel.internal", "-gate-address", "192.0.2.53", "-dns-search-suffix", "svc.cluster.example"), &stdout, &stderr)
	}()
	select {
	case <-l.ready:
	case code := <-done:
		t.Fatalf("run returned %d before listening; stderr: %s", code, stderr.String())
	case <-time.After(10 * time.Second):
		t.Fatal("it did not listen")
	}

	l.mu.Lock()
	dnsAddr := l.addrs["workspace/dns-udp"].String()
	l.mu.Unlock()
	c, err := net.Dial("udp", dnsAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 7})
	_ = b.StartQuestions()
	_ = b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName("sentinel.internal."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
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
	if err := m.Unpack(buf[:n]); err != nil || len(m.Answers) != 1 {
		t.Fatalf("answer = %+v, %v", m, err)
	}
	if a := m.Answers[0].Body.(*dnsmessage.AResource).A; a != [4]byte{192, 0, 2, 53} {
		t.Errorf("the gate's name = %v, want 192.0.2.53", a)
	}

	// The owner's door answers on its socket.
	oc := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", s.approvals)
	}}, Timeout: 5 * time.Second}
	resp, err := oc.Get("http://sentinel/v1/approvals")
	if err != nil {
		t.Fatalf("the approvals socket: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("GET /v1/approvals on the socket = %d", resp.StatusCode)
	}

	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Errorf("run = %d after being stopped, want 0; stderr: %s", code, stderr.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("it did not stop")
	}

	if !strings.Contains(stdout.String(), `"kind":"dns"`) {
		t.Errorf("stdout = %q, want the query's record copied", stdout.String())
	}
	db, err := sql.Open("sqlite", s.db)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var count int
	if err := db.QueryRow(`SELECT count(*) FROM records WHERE kind = 'dns' AND name = 'sentinel.internal'`).Scan(&count); err != nil || count != 1 {
		t.Errorf("records of the query in SQLite = %d, %v; want 1", count, err)
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

func TestASearchSuffixMustBeAName(t *testing.T) {
	for _, suffix := range []string{"", ".", "with space.example", "a..example"} {
		t.Run(suffix, func(t *testing.T) {
			s := newSetup(t)
			var stdout, stderr bytes.Buffer
			if code := run(context.Background(), s.args("-dns-search-suffix", suffix), &stdout, &stderr); code != 2 {
				t.Fatalf("run = %d, want 2; stderr: %s", code, stderr.String())
			}
			if !strings.Contains(stderr.String(), "-dns-search-suffix") {
				t.Errorf("stderr %q does not name -dns-search-suffix", stderr.String())
			}
		})
	}
}
