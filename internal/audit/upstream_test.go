package audit_test

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/yuanying/natsumi-sentinel/internal/audit"
)

func TestTheAddressesTheGateConnectedToAreKept(t *testing.T) {
	l, out, _ := openLog(t)
	ctx := context.Background()
	rec := &audit.Record{Time: at, Source: "workspace", Kind: audit.KindHTTP, Name: "docs.example.net", Verdict: audit.Deny,
		UpstreamAddress: []string{"10.0.0.1:443", "[fd00::1]:443"}}
	if err := l.Write(ctx, rec); err != nil {
		t.Fatal(err)
	}
	got, err := l.Get(ctx, rec.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.UpstreamAddress, rec.UpstreamAddress) {
		t.Errorf("upstreamAddress = %v", got.UpstreamAddress)
	}
	var line map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(out.String())), &line); err != nil {
		t.Fatal(err)
	}
	if _, ok := line["upstreamAddress"]; !ok {
		t.Errorf("the copy has no upstreamAddress: %s", out.String())
	}

	begun := &audit.Record{Time: at, Source: "workspace", Kind: audit.KindPassthrough, Name: "k8s.example.net", Verdict: audit.Allow}
	if err := l.Begin(ctx, begun); err != nil {
		t.Fatal(err)
	}
	begun.UpstreamAddress = []string{"203.0.113.5:443"}
	if err := l.Finish(ctx, begun); err != nil {
		t.Fatal(err)
	}
	if got, _ := l.Get(ctx, begun.ID); !slices.Equal(got.UpstreamAddress, []string{"203.0.113.5:443"}) {
		t.Errorf("finished upstreamAddress = %v", got.UpstreamAddress)
	}
}

func TestARecordTheGateDidNotConnectForHasNoUpstreamAddress(t *testing.T) {
	l, out, _ := openLog(t)
	rec := &audit.Record{Time: at, Kind: audit.KindDNS, Name: "a.example.com", Verdict: audit.Deny}
	if err := l.Write(context.Background(), rec); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "upstreamAddress") {
		t.Errorf("copy = %s", out.String())
	}
	if got, _ := l.Get(context.Background(), rec.ID); got.UpstreamAddress != nil {
		t.Errorf("upstreamAddress = %v", got.UpstreamAddress)
	}
}
