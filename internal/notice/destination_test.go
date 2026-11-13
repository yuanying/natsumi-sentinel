package notice_test

import (
	"strings"
	"testing"
	"time"

	"github.com/yuanying/natsumi-sentinel/internal/audit"
	"github.com/yuanying/natsumi-sentinel/internal/ledger"
	"github.com/yuanying/natsumi-sentinel/internal/notice"
)

func TestAPassthroughAGrantLetThroughIsItsNameAndPort(t *testing.T) {
	rec := audit.Record{Kind: audit.KindPassthrough, Name: "k8s.example.net", Address: "198.51.100.9:443", Grant: "gr-1", Verdict: audit.Allow}
	if got := pairs(rec); got != "[granted-passthrough=k8s.example.net:443]" {
		t.Errorf("pairs = %s", got)
	}
	rec.Verdict = audit.Deny
	if got := pairs(rec); got != "[]" {
		t.Errorf("refused: pairs = %s", got)
	}
}

func TestAnAllowedApprovalOfDestinationsIsToldWithItsNamesAndOptions(t *testing.T) {
	end := at.Add(time.Hour)
	_ = end
	a := &ledger.Approval{
		ID: "ap-d", Kind: ledger.KindDestination, State: ledger.Allowed, Source: "workspace",
		Items:   []ledger.Facts{{Destination: "docs.example.net"}, {Destination: "cdn.example.net"}},
		Choices: []ledger.Choice{{ID: "1h", Scope: ledger.ScopeTimed, Seconds: 3600}},
		Choice:  "1h", Chosen: &ledger.OptionAnswer{Unit: "name", Handling: "inspect", Access: "read"},
		Grants: []string{"gr-a", "gr-b"}, Answered: &at,
	}
	n := notice.Answered(a)
	wantTold(t, n, "ap-d", "docs.example.net", "cdn.example.net", "unit=name", "handling=inspect", "access=read", "gr-a", "workspace", "destinations asked for beforehand")
	if strings.Contains(n.Summary, " on docs") {
		t.Errorf("summary = %q", n.Summary)
	}
}

func destGrant() *ledger.Grant {
	end := at.Add(time.Hour)
	return &ledger.Grant{ID: "gr-l", Kind: ledger.GrantDestination, Source: "workspace", Scope: ledger.ScopeTimed, Created: at, Expires: &end,
		Name: "example.net", Unit: ledger.UnitDomain, Handling: ledger.Passthrough, Summary: "example.net itself and every name under it; passed through"}
}

func TestAGrantFromTheListOfRefusedNamesIsToldAsAnAnswer(t *testing.T) {
	n := notice.GrantedFromList(destGrant(), at)
	if n.Type != notice.TypeAnswer || n.Labels["answer"] != "allowed" || n.Labels["approval"] != "" || n.Labels["grant"] != "gr-l" || n.Labels["source"] != "workspace" {
		t.Errorf("notice = %+v", n)
	}
	wantTold(t, n, "example.net", "domain", "passthrough", "2026-11-11T10:30:00Z", "list of refused names")
}

func TestARevokedDestinationGrantIsToldWithItsName(t *testing.T) {
	n := notice.Revoked(destGrant(), at)
	wantTold(t, n, "gr-l", "example.net", "domain", "passthrough")
	if strings.Contains(n.Summary, " on ") {
		t.Errorf("summary = %q", n.Summary)
	}
}
