package authdclient_test

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yuanying/natsumi-sentinel/internal/authdclient"
)

// fakeAuthd serves handler on a Unix socket and returns the socket's path.
func fakeAuthd(t *testing.T, handler http.HandlerFunc) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "authdclient")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "authd.sock")
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	return path
}

func newTransport(t *testing.T, path string) *authdclient.Transport {
	t.Helper()
	tr := authdclient.NewTransport(path)
	t.Cleanup(tr.CloseIdleConnections)
	return tr
}

func TestTheRequestReachesAuthdWithTheUpstreamAsItsHostAndThePathAndQueryUnchanged(t *testing.T) {
	type seen struct{ host, uri, auth, body string }
	got := make(chan seen, 1)
	path := fakeAuthd(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got <- seen{r.Host, r.RequestURI, r.Header.Get("Authorization"), string(b)}
		w.WriteHeader(http.StatusCreated)
	})

	req, _ := http.NewRequest(http.MethodPost, "https://api.example.com:8443/repos/a%2Fb/issues?state=open&x=%20", strings.NewReader("the body"))
	req.Header.Set("Authorization", "Bearer surrogate-for-the-test")
	resp, err := newTransport(t, path).RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("status = %d, want 201", resp.StatusCode)
	}
	s := <-got
	if s.host != "api.example.com:8443" {
		t.Errorf("Host = %q, want api.example.com:8443", s.host)
	}
	if s.uri != "/repos/a%2Fb/issues?state=open&x=%20" {
		t.Errorf("request URI = %q", s.uri)
	}
	if s.auth != "Bearer surrogate-for-the-test" {
		t.Errorf("Authorization = %q, want the surrogate as the gate gave it", s.auth)
	}
	if s.body != "the body" {
		t.Errorf("body = %q", s.body)
	}
}

func TestAnUpstreamWithoutAPortIsSentWithPort443(t *testing.T) {
	got := make(chan string, 1)
	path := fakeAuthd(t, func(w http.ResponseWriter, r *http.Request) { got <- r.Host })
	req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/", nil)
	resp, err := newTransport(t, path).RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if h := <-got; h != "api.example.com:443" {
		t.Errorf("Host = %q, want api.example.com:443", h)
	}
}

func TestTheTransportAddsNoAcceptEncodingOfItsOwn(t *testing.T) {
	got := make(chan string, 1)
	path := fakeAuthd(t, func(w http.ResponseWriter, r *http.Request) { got <- r.Header.Get("Accept-Encoding") })
	req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/", nil)
	resp, err := newTransport(t, path).RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if ae := <-got; ae != "" {
		t.Errorf("Accept-Encoding = %q, want none: the gate passes on what the workspace sent", ae)
	}
}

func TestAnythingButHTTPSIsRefusedWithoutReachingAuthd(t *testing.T) {
	reached := make(chan struct{}, 1)
	path := fakeAuthd(t, func(w http.ResponseWriter, r *http.Request) { reached <- struct{}{} })
	req, _ := http.NewRequest(http.MethodGet, "http://api.example.com/", nil)
	if resp, err := newTransport(t, path).RoundTrip(req); err == nil {
		_ = resp.Body.Close()
		t.Fatal("RoundTrip of an http URL succeeded")
	}
	select {
	case <-reached:
		t.Error("authd was reached")
	default:
	}
}

func TestAHostThatDiffersFromTheURLIsRefusedWithoutReachingAuthd(t *testing.T) {
	reached := make(chan struct{}, 1)
	path := fakeAuthd(t, func(w http.ResponseWriter, r *http.Request) { reached <- struct{}{} })
	req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/", nil)
	req.Host = "other.example.com"
	if resp, err := newTransport(t, path).RoundTrip(req); err == nil {
		_ = resp.Body.Close()
		t.Fatal("RoundTrip with a different Host succeeded")
	}
	select {
	case <-reached:
		t.Error("authd was reached")
	default:
	}
}

func TestAnAuthdRefusalComesBackAsAnErrorThatCarriesTheReason(t *testing.T) {
	path := fakeAuthd(t, func(w http.ResponseWriter, r *http.Request) {
		authdclient.WriteError(w, &authdclient.Error{
			Reason:  authdclient.ReasonSurrogateMismatch,
			Message: "the surrogate is not registered for this upstream",
		})
	})
	req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/", nil)
	resp, err := newTransport(t, path).RoundTrip(req)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("RoundTrip succeeded, want an error")
	}
	var aerr *authdclient.Error
	if !errors.As(err, &aerr) {
		t.Fatalf("error %T %v is not an *authdclient.Error", err, err)
	}
	if aerr.Reason != authdclient.ReasonSurrogateMismatch {
		t.Errorf("Reason = %q", aerr.Reason)
	}
	if aerr.Message != "the surrogate is not registered for this upstream" {
		t.Errorf("Message = %q", aerr.Message)
	}
	if !aerr.Refused() {
		t.Error("Refused() = false for a surrogate mismatch")
	}
}

func TestAFailureToReachTheUpstreamIsAnErrorButNotARefusal(t *testing.T) {
	path := fakeAuthd(t, func(w http.ResponseWriter, r *http.Request) {
		authdclient.WriteError(w, &authdclient.Error{Reason: authdclient.ReasonUpstreamCertificate, Message: "x"})
	})
	req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/", nil)
	_, err := newTransport(t, path).RoundTrip(req)
	var aerr *authdclient.Error
	if !errors.As(err, &aerr) {
		t.Fatalf("error %v is not an *authdclient.Error", err)
	}
	if aerr.Refused() {
		t.Error("Refused() = true for a certificate failure")
	}
}

func TestAnUpstreamsOwn403IsAResponseNotAnError(t *testing.T) {
	path := fakeAuthd(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "upstream says no", http.StatusForbidden)
	})
	req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/", nil)
	resp, err := newTransport(t, path).RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestTheResponseBodyIsHandedOnAsItArrives(t *testing.T) {
	release := make(chan struct{})
	path := fakeAuthd(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "first\n")
		w.(http.Flusher).Flush()
		<-release
		_, _ = io.WriteString(w, "second\n")
	})
	defer close(release)
	req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/watch", nil)
	resp, err := newTransport(t, path).RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	line := make(chan string, 1)
	go func() {
		s, _ := bufio.NewReader(resp.Body).ReadString('\n')
		line <- s
	}()
	select {
	case s := <-line:
		if s != "first\n" {
			t.Errorf("first line = %q", s)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the first line did not arrive before the response ended")
	}
}

func TestCancellingTheRequestEndsTheRoundTrip(t *testing.T) {
	path := fakeAuthd(t, func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.example.com/", nil)
	if resp, err := newTransport(t, path).RoundTrip(req); err == nil {
		_ = resp.Body.Close()
		t.Fatal("RoundTrip succeeded after the context ended")
	}
}

func TestAMissingSocketIsAnErrorThatIsNotAnAuthdError(t *testing.T) {
	tr := authdclient.NewTransport(filepath.Join(t.TempDir(), "no.sock"))
	req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/", nil)
	_, err := tr.RoundTrip(req)
	if err == nil {
		t.Fatal("RoundTrip to a missing socket succeeded")
	}
	var aerr *authdclient.Error
	if errors.As(err, &aerr) {
		t.Errorf("error is an *authdclient.Error: %v", err)
	}
}
