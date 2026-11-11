package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// running is a gate started by startGate.
type running struct {
	t              *testing.T
	mu             *sync.Mutex
	addrs          map[string]net.Addr
	stdout, stderr *syncBuffer
	stop           func() int
}

// startGate runs the gate, and waits until it listens on each of want
// ("workspace/dns-udp", "metrics", ...). The caller builds an upstream
// sender in first.
func startGate(t *testing.T, s setup, want []string, extra ...string) *running {
	t.Helper()
	var mu sync.Mutex
	addrs := map[string]net.Addr{}
	ready := make(chan struct{})
	old := onListen
	onListen = func(source, what string, addr net.Addr) {
		mu.Lock()
		defer mu.Unlock()
		key := what
		if source != "" {
			key = source + "/" + what
		}
		addrs[key] = addr
		for _, w := range want {
			if addrs[w] == nil {
				return
			}
		}
		select {
		case <-ready:
		default:
			close(ready)
		}
	}
	t.Cleanup(func() { onListen = old })

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	r := &running{t: t, mu: &mu, addrs: addrs, stdout: &syncBuffer{}, stderr: &syncBuffer{}}
	go func() { done <- run(ctx, s.args(extra...), r.stdout, r.stderr) }()
	select {
	case <-ready:
	case code := <-done:
		cancel()
		t.Fatalf("run returned %d before listening; stderr: %s", code, r.stderr.String())
	case <-time.After(10 * time.Second):
		cancel()
		t.Fatal("it did not listen")
	}
	var once sync.Once
	code := 0
	r.stop = func() int {
		once.Do(func() {
			cancel()
			select {
			case code = <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("it did not stop")
			}
		})
		return code
	}
	t.Cleanup(func() { r.stop() })
	return r
}

// addr is where the gate listens for what ("workspace/dns-udp", ...), or
// nil.
func (r *running) addr(what string) net.Addr {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.addrs[what]
}

// query asks the gate's name resolution for name and returns the rcode.
func (r *running) query(name string) dnsmessage.RCode {
	r.t.Helper()
	c, err := net.Dial("udp", r.addr("workspace/dns-udp").String())
	if err != nil {
		r.t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 7})
	_ = b.StartQuestions()
	_ = b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name + "."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	q, _ := b.Finish()
	if _, err := c.Write(q); err != nil {
		r.t.Fatal(err)
	}
	buf := make([]byte, 512)
	n, err := c.Read(buf)
	if err != nil {
		r.t.Fatalf("no answer: %v", err)
	}
	var m dnsmessage.Message
	if err := m.Unpack(buf[:n]); err != nil {
		r.t.Fatal(err)
	}
	return m.RCode
}

func (r *running) metrics() string {
	r.t.Helper()
	resp, err := http.Get("http://" + r.addr("metrics").String() + "/metrics")
	if err != nil {
		r.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

func TestTheMetricsCountWhatIsRecorded(t *testing.T) {
	withUpstream(t)
	r := startGate(t, newSetup(t), []string{"workspace/dns-udp", "metrics"}, "-metrics-listen", "127.0.0.1:0")
	if rc := r.query("unknown.example.net"); rc != dnsmessage.RCodeNameError {
		t.Fatalf("rcode = %v, want NXDOMAIN", rc)
	}
	page := r.metrics()
	for _, want := range []string{
		`sentinel_requests_total{destination="(not-listed)",kind="dns",source="workspace",treatment="deny",verdict="deny"} 1`,
		`sentinel_build_info{version="dev"} 1`,
		`sentinel_audit_write_failures_total{stage="write"} 0`,
		`sentinel_routes_reload_failures_total 0`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the metrics do not carry %q", want)
		}
	}
}

func TestWithoutAMetricsAddressNoneAreServed(t *testing.T) {
	withUpstream(t)
	r := startGate(t, newSetup(t), []string{"workspace/dns-udp"})
	r.query("unknown.example.net")
	if code := r.stop(); code != 0 {
		t.Fatalf("run = %d, want 0", code)
	}
	if r.addr("metrics") != nil {
		t.Error("metrics were listened for without -metrics-listen")
	}
}

func TestAMetricsAddressThatCannotBeListenedOnStopsTheStart(t *testing.T) {
	withUpstream(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	s := newSetup(t)
	var stdout, stderr syncBuffer
	if code := run(context.Background(), s.args("-metrics-listen", ln.Addr().String()), &stdout, &stderr); code != 1 {
		t.Fatalf("run = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "metrics") {
		t.Errorf("stderr = %q, want it to say the metrics are the trouble", stderr.String())
	}
}

func TestAStartThatFailsAfterTheMetricsAreServedStillEnds(t *testing.T) {
	withUpstream(t)
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = busy.Close() }()
	s := newSetup(t)
	args := s.args("-metrics-listen", "127.0.0.1:0")
	for i, a := range args {
		if a == "-source" {
			args[i+1] = "name=workspace,proxy=" + busy.Addr().String() + ",dns=127.0.0.1:0"
		}
	}
	done := make(chan int, 1)
	go func() {
		var stdout, stderr syncBuffer
		done <- run(context.Background(), args, &stdout, &stderr)
	}()
	select {
	case code := <-done:
		if code != 1 {
			t.Errorf("run = %d, want 1", code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not return after the proxy could not be listened on")
	}
}
