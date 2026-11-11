package audit_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"strings"
	"testing"

	"github.com/yuanying/natsumi-sentinel/internal/audit"
)

func sum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func TestABodyWithinTheLimitIsKeptWholeBeforeItIsSent(t *testing.T) {
	body := []byte(`{"body":"hello"}`)
	c, r, err := audit.CaptureBody(bytes.NewReader(body), 1024)
	if err != nil {
		t.Fatalf("CaptureBody: %v", err)
	}
	before := c.Summary()
	if before.Text != string(body) || before.Truncated || before.Binary || before.Size != int64(len(body)) || before.SHA256 != sum(body) {
		t.Errorf("Summary before sending = %+v", before)
	}
	sent, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sent, body) {
		t.Errorf("sent %q, want %q", sent, body)
	}
}

func TestABodyOverTheLimitKeepsItsStartAndIsMeasuredWhileItIsSent(t *testing.T) {
	body := []byte(strings.Repeat("a", 100))
	c, r, err := audit.CaptureBody(bytes.NewReader(body), 10)
	if err != nil {
		t.Fatalf("CaptureBody: %v", err)
	}
	before := c.Summary()
	if before.Text != "aaaaaaaaaa" || !before.Truncated || before.SHA256 != "" {
		t.Errorf("Summary before sending = %+v; want the first 10 bytes, truncated, no hash yet", before)
	}
	sent, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sent, body) {
		t.Errorf("sent %d bytes, want the whole body", len(sent))
	}
	after := c.Summary()
	if after.Size != 100 || after.SHA256 != sum(body) || after.Text != "aaaaaaaaaa" || !after.Truncated {
		t.Errorf("Summary after sending = %+v", after)
	}
}

func TestABodyExactlyAtTheLimitIsNotTruncated(t *testing.T) {
	body := []byte("0123456789")
	c, _, err := audit.CaptureBody(bytes.NewReader(body), 10)
	if err != nil {
		t.Fatal(err)
	}
	if s := c.Summary(); s.Truncated || s.Text != "0123456789" || s.SHA256 != sum(body) {
		t.Errorf("Summary = %+v", s)
	}
}

func TestABinaryBodyKeepsOnlyItsSizeAndHash(t *testing.T) {
	body := []byte{0x1f, 0x8b, 0x08, 0x00, 0xff, 0xfe}
	c, r, err := audit.CaptureBody(bytes.NewReader(body), 1024)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(r)
	if s := c.Summary(); s.Text != "" || !s.Binary || s.Size != 6 || s.SHA256 != sum(body) {
		t.Errorf("Summary = %+v", s)
	}
}

func TestACutInTheMiddleOfACharacterIsStillText(t *testing.T) {
	body := []byte("あいう") // 9 bytes, 3 per character
	c, _, err := audit.CaptureBody(bytes.NewReader(body), 4)
	if err != nil {
		t.Fatal(err)
	}
	if s := c.Summary(); s.Binary || s.Text != "あ" || !s.Truncated {
		t.Errorf("Summary = %+v; want the whole characters before the cut", s)
	}
}

func TestALimitOfZeroKeepsNoTextButStillMeasures(t *testing.T) {
	body := []byte("hello")
	c, r, err := audit.CaptureBody(bytes.NewReader(body), 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(r)
	if s := c.Summary(); s.Text != "" || !s.Truncated || s.Size != 5 || s.SHA256 != sum(body) {
		t.Errorf("Summary = %+v", s)
	}
}

func TestAnEmptyBodyIsAnEmptySummary(t *testing.T) {
	c, _, err := audit.CaptureBody(bytes.NewReader(nil), 10)
	if err != nil {
		t.Fatal(err)
	}
	if s := c.Summary(); s.Size != 0 || s.Truncated || s.Binary || s.Text != "" {
		t.Errorf("Summary = %+v", s)
	}
}
