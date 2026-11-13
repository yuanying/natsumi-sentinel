package observe_test

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/yuanying/natsumi-sentinel/internal/ledger"
	"github.com/yuanying/natsumi-sentinel/internal/metrics"
	"github.com/yuanying/natsumi-sentinel/internal/observe"
	"github.com/yuanying/natsumi-sentinel/internal/upstream"
)

type fakeDirect struct{ err error }

func (f fakeDirect) RoundTrip(*http.Request) (*http.Response, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
}

func (f fakeDirect) Dial(context.Context, string, uint16) (*upstream.Conn, error) {
	if f.err != nil {
		return nil, f.err
	}
	a, _ := net.Pipe()
	return &upstream.Conn{Conn: a}, nil
}

func TestTheGatesOwnSendingIsCountedByItsReasonsWithoutTheName(t *testing.T) {
	reg := metrics.NewRegistry("sentinel", "dev")
	m := observe.NewGateMetrics(reg, table(t), nil)
	for _, r := range []upstream.Reason{upstream.ReasonAddressPrivate, upstream.ReasonSurrogate, upstream.ReasonUnreachable} {
		d := m.Direct(fakeDirect{err: &upstream.Error{Reason: r}})
		req, _ := http.NewRequest(http.MethodGet, "https://made-up.example.net/", nil)
		_, _ = d.RoundTrip(req)
	}
	d := m.Direct(fakeDirect{err: &upstream.Error{Reason: upstream.ReasonAddressLocal}})
	_, _ = d.Dial(context.Background(), "made-up.example.net", 443)
	ok := m.Direct(fakeDirect{})
	if c, err := ok.Dial(context.Background(), "x.example.net", 443); err != nil || c == nil {
		t.Errorf("dial = %v, %v", c, err)
	}
	wantLines(t, page(t, reg),
		`sentinel_upstream_failures_total{destination="(not-listed)",reason="upstream-address-private"} 1`,
		`sentinel_upstream_failures_total{destination="(not-listed)",reason="surrogate-unswapped"} 1`,
		`sentinel_upstream_failures_total{destination="(not-listed)",reason="upstream-unreachable"} 1`,
		`sentinel_upstream_failures_total{destination="(not-listed)",reason="upstream-address-local"} 1`,
	)
}

func TestTheDestinationGrantsAndRefusedNamesAreCounted(t *testing.T) {
	reg := metrics.NewRegistry("sentinel", "dev")
	var err error
	dm := observe.NewDestinationMetrics(reg,
		func(context.Context) (map[ledger.GrantShape]int, error) {
			return map[ledger.GrantShape]int{{Handling: ledger.Inspect, Access: ledger.Read}: 2, {Handling: ledger.Passthrough}: 1}, err
		},
		func(context.Context) (int, error) { return 7, err }, nil)
	dm.Remembered(2, nil)
	dm.Remembered(0, errors.New("disk full"))
	wantLines(t, page(t, reg),
		`sentinel_destination_grants{access="read",handling="inspect"} 2`,
		`sentinel_destination_grants{access="",handling="passthrough"} 1`,
		`sentinel_refused_names 7`,
		`sentinel_refused_names_dropped_total 2`,
		`sentinel_refused_names_unkept_total 1`,
	)
	err = errors.New("locked")
	if got := page(t, reg); strings.Contains(got, "sentinel_refused_names 7") || strings.Contains(got, "sentinel_destination_grants{") {
		t.Errorf("served counts the ledger did not give:\n%s", got)
	}
}
