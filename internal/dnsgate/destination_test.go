package dnsgate_test

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/yuanying/natsumi-sentinel/internal/audit"
	"github.com/yuanying/natsumi-sentinel/internal/decide"
	"github.com/yuanying/natsumi-sentinel/internal/dnsgate"
	"github.com/yuanying/natsumi-sentinel/internal/routes"
)

// answers is a NameDecider that answers each name as told.
type answers map[string]decide.NameAnswer

func (a answers) DecideName(_ context.Context, q decide.NameQuery) decide.NameAnswer {
	if ans, ok := a[q.Name]; ok {
		return ans
	}
	return decide.NameAnswer{Verdict: audit.Deny, Treatment: routes.Closed, Reason: audit.ReasonDNSNotListed}
}

type keeper struct {
	mu      sync.Mutex
	kept    []string
	err     error
	dropped int
}

func (k *keeper) RememberRefused(_ context.Context, source, name string) (int, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.err != nil {
		return 0, k.err
	}
	k.kept = append(k.kept, source+" "+name)
	return k.dropped, nil
}

type lookups struct {
	mu    sync.Mutex
	names []string
}

func (l *lookups) LookupNetIP(_ context.Context, network, host string) ([]netip.Addr, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.names = append(l.names, host)
	if network == "ip4" {
		return []netip.Addr{netip.MustParseAddr("203.0.113.5")}, nil
	}
	return []netip.Addr{netip.MustParseAddr("2001:db8::5")}, nil
}

type remembered struct {
	dropped int
	errs    int
}

func grantServer(t *testing.T, names answers, k *keeper) (*dnsgate.Server, *memLog, *lookups, *remembered) {
	t.Helper()
	log, res, rem := &memLog{}, &lookups{}, &remembered{}
	cfg := dnsgate.Config{
		Source:   "workspace",
		Routes:   func() *routes.Table { return nil },
		Names:    names,
		Resolver: res,
		Log:      log,
		Remembered: func(dropped int, err error) {
			rem.dropped += dropped
			if err != nil {
				rem.errs++
			}
		},
	}
	if k != nil {
		cfg.Refused = k
	}
	return dnsgate.New(cfg), log, res, rem
}

func TestANameAnsweredOnADestinationGrantIsLookedUpAndRecordedWithTheGrant(t *testing.T) {
	s, log, res, _ := grantServer(t, answers{"docs.example.net": {Verdict: audit.Allow, Treatment: routes.Open, Grant: "gr-1", Reason: decide.ReasonDNSGranted + ": gr-1"}}, &keeper{})
	m := parse(t, s.Answer(context.Background(), query(t, "docs.example.net.", dnsmessage.TypeA)))
	if m.RCode != dnsmessage.RCodeSuccess || len(aAnswers(m)) != 1 {
		t.Fatalf("answer = %+v", m)
	}
	rec := log.last(t)
	if rec.Verdict != audit.Allow || rec.Grant != "gr-1" || rec.Treatment != "open" || !strings.Contains(rec.Reason, "gr-1") {
		t.Errorf("record = %+v", rec)
	}
	if len(res.names) != 1 {
		t.Errorf("looked up %v", res.names)
	}
}

func TestAPassthroughGrantIsRecordedAsPassthrough(t *testing.T) {
	s, log, _, _ := grantServer(t, answers{"k8s.example.net": {Verdict: audit.Allow, Treatment: "passthrough", Grant: "gr-2", Reason: "r"}}, &keeper{})
	s.Answer(context.Background(), query(t, "k8s.example.net.", dnsmessage.TypeA))
	if rec := log.last(t); rec.Treatment != "passthrough" || rec.Grant != "gr-2" {
		t.Errorf("record = %+v", rec)
	}
}

func TestARefusedNameIsRememberedAndNeverLookedUp(t *testing.T) {
	k := &keeper{dropped: 1}
	s, log, res, rem := grantServer(t, answers{"new.example.net": {Verdict: audit.Deny, Treatment: routes.Closed, Reason: audit.ReasonDNSNotListed, Remember: true}}, k)
	for _, typ := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA, dnsmessage.TypeTXT} {
		m := parse(t, s.Answer(context.Background(), query(t, "new.example.net.", typ)))
		if m.RCode != dnsmessage.RCodeNameError {
			t.Errorf("%v: rcode %v", typ, m.RCode)
		}
	}
	if len(k.kept) != 3 || k.kept[0] != "workspace new.example.net" {
		t.Errorf("kept %v", k.kept)
	}
	if len(res.names) != 0 {
		t.Errorf("looked up %v", res.names)
	}
	if rem.dropped != 3 {
		t.Errorf("dropped told %d", rem.dropped)
	}
	if rec := log.last(t); rec.Error != "" {
		t.Errorf("record = %+v", rec)
	}
}

func TestANameNotToRememberIsNotKept(t *testing.T) {
	k := &keeper{}
	s, _, _, _ := grantServer(t, answers{}, k)
	s.Answer(context.Background(), query(t, "x.example.net.", dnsmessage.TypeA))
	if len(k.kept) != 0 {
		t.Errorf("kept %v", k.kept)
	}
}

func TestANameThatCannotBeRememberedIsStillRefusedAndTheFailureRecorded(t *testing.T) {
	k := &keeper{err: errors.New("disk full")}
	s, log, _, rem := grantServer(t, answers{"new.example.net": {Verdict: audit.Deny, Treatment: routes.Closed, Reason: audit.ReasonDNSNotListed, Remember: true}}, k)
	m := parse(t, s.Answer(context.Background(), query(t, "new.example.net.", dnsmessage.TypeA)))
	if m.RCode != dnsmessage.RCodeNameError {
		t.Errorf("rcode %v", m.RCode)
	}
	rec := log.last(t)
	if !strings.Contains(rec.Error, "could not be remembered") || rec.Reason != audit.ReasonDNSNotListed {
		t.Errorf("record = %+v", rec)
	}
	if rem.errs != 1 {
		t.Errorf("errors told %d", rem.errs)
	}
}

func TestALedgerThatCouldNotBeReadIsInTheRecord(t *testing.T) {
	s, log, _, _ := grantServer(t, answers{"docs.example.net": {Verdict: audit.Deny, Treatment: routes.Closed, Reason: "r", Error: "disk gone"}}, &keeper{})
	m := parse(t, s.Answer(context.Background(), query(t, "docs.example.net.", dnsmessage.TypeA)))
	if m.RCode != dnsmessage.RCodeNameError || log.last(t).Error != "disk gone" {
		t.Errorf("rcode %v, record %+v", m.RCode, log.last(t))
	}
}
