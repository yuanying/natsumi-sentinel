package notice_test

import (
	"fmt"
	"testing"

	"github.com/yuanying/natsumi-sentinel/internal/audit"
	"github.com/yuanying/natsumi-sentinel/internal/notice"
)

func pairs(rec audit.Record) string {
	var out []string
	for _, s := range notice.Pairs(&rec) {
		out = append(out, s.Pair+"="+s.Key)
	}
	return fmt.Sprint(out)
}

func TestThePairsOfARecord(t *testing.T) {
	tests := map[string]struct {
		rec  audit.Record
		want string
	}{
		"a read let through is its destination": {
			audit.Record{Kind: audit.KindHTTP, Name: "api.example.com", Method: "GET", Path: "/repos/o/r", Query: "page=2", Verdict: audit.Allow},
			"[destination=api.example.com]",
		},
		"a write let through is its destination and the write": {
			audit.Record{Kind: audit.KindHTTP, Name: "api.example.com", Method: "POST", Path: "/repos/o/r/issues", Query: "x=1", Verdict: audit.Allow},
			"[destination=api.example.com write=api.example.com POST /repos/o/r/issues]",
		},
		"a refused request is no pair": {
			audit.Record{Kind: audit.KindHTTP, Name: "api.example.com", Method: "DELETE", Path: "/repos/o/r", Verdict: audit.Deny},
			"[]",
		},
		"a passthrough is its address and port": {
			audit.Record{Kind: audit.KindPassthrough, Address: "192.0.2.10:5432", Verdict: audit.Allow},
			"[passthrough=192.0.2.10:5432]",
		},
		"a name refused in name resolution": {
			audit.Record{Kind: audit.KindDNS, Treatment: "deny", Name: "made-up.example.net", Verdict: audit.Deny},
			"[denied-name=made-up.example.net]",
		},
		"a name answered is no pair": {
			audit.Record{Kind: audit.KindDNS, Treatment: "open", Name: "api.example.com", Verdict: audit.Allow},
			"[]",
		},
		"a refused connection is no pair": {
			audit.Record{Kind: audit.KindConnection, Treatment: "deny", Name: "made-up.example.net", Verdict: audit.Deny},
			"[]",
		},
		"the gate's own request is no pair": {
			audit.Record{Kind: audit.KindGate, Name: "alerts.example.com", Method: "POST", Path: "/api/v2/alerts", Verdict: audit.Allow},
			"[]",
		},
		"reading the table again is no pair": {
			audit.Record{Kind: audit.KindConfig, Verdict: audit.Allow},
			"[]",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := pairs(tt.rec); got != tt.want {
				t.Errorf("Pairs = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestAPairIsSeenAtItsRecordsTimeAndId(t *testing.T) {
	ps := notice.Pairs(&audit.Record{ID: 42, Time: at, Kind: audit.KindHTTP, Name: "api.example.com", Method: "GET", Verdict: audit.Allow})
	if len(ps) != 1 || ps[0].Record != 42 || !ps[0].First.Equal(at) {
		t.Errorf("Pairs = %+v, want one pair of record 42 at %v", ps, at)
	}
}
