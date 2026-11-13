package gate

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/yuanying/natsumi-sentinel/internal/audit"
	"github.com/yuanying/natsumi-sentinel/internal/decide"
	"github.com/yuanying/natsumi-sentinel/internal/upstream"
)

// This file is what the gate does with what a destination grant lets
// through (docs/adr/0008, docs/destination-grants.md "接続と要求"): the
// gate sends it upstream itself, with its own sending, to the name looked
// up again.

// DirectSender is the gate's own sending: *upstream.Sender is one.
type DirectSender interface {
	http.RoundTripper
	Dial(ctx context.Context, name string, port uint16) (*upstream.Conn, error)
}

// MarkInsidePublic is put at the end of the reason of a record of an
// inside name that was connected to a public address (docs/adr/0008: the
// inside name's DNS may have been taken to point outside).
const MarkInsidePublic = "; an inside name connected to a public address"

// helloConn is a connection whose TLS handshake is kept as it is read,
// and whose writes can be muted: a handshake the gate does not finish is
// handed on whole, with nothing of the gate's side of it sent.
type helloConn struct {
	net.Conn
	keep, mute bool
	kept       bytes.Buffer
}

func (h *helloConn) Read(b []byte) (int, error) {
	n, err := h.Conn.Read(b)
	if h.keep && n > 0 {
		h.kept.Write(b[:n])
	}
	return n, err
}

func (h *helloConn) Write(b []byte) (int, error) {
	if h.mute {
		return len(b), nil
	}
	return h.Conn.Write(b)
}

// reported puts where the gate's own sending connected, or the addresses
// it would not connect to, into the record, with the marks of an inside
// name.
func reported(rec *audit.Record, rep upstream.Report, err error) {
	if rep.Address.IsValid() {
		rec.UpstreamAddress = []string{rep.Address.String()}
		if rep.InsidePublic {
			rec.Reason += MarkInsidePublic
		}
		return
	}
	var ue *upstream.Error
	if errors.As(err, &ue) {
		for _, a := range ue.Resolved {
			rec.UpstreamAddress = append(rec.UpstreamAddress, netip.AddrPortFrom(a.Unmap(), upstream.Port).String())
		}
	}
}

// directFailure puts why the gate's own sending did not send, or got no
// answer, into the record, and gives the status and text to answer the
// workspace with. A refusal (an address never connected to, a surrogate)
// is the gate's deny; a failure to reach the upstream is the gate's error
// (docs/gate-responses.md).
func directFailure(rec *audit.Record, err error) (int, string, string) {
	var ue *upstream.Error
	if !errors.As(err, &ue) {
		rec.Error = "the gate could not send the request: " + err.Error()
		return http.StatusBadGateway, MarkError, "the gate could not send the request upstream"
	}
	if ue.Refused() {
		rec.Verdict = audit.Deny
		rec.Error = "the gate refused to send the request: " + ue.Error()
		return http.StatusForbidden, MarkDeny, "the gate refused to send the request (" + string(ue.Reason) + "): " + ue.Message
	}
	rec.Error = "the gate could not get an answer from the upstream: " + ue.Error()
	return http.StatusBadGateway, MarkError, "the gate could not get an answer from the upstream (" + string(ue.Reason) + "): " + ue.Message
}

// grantedPassthrough connects a connection a destination grant passes
// through to the name of its SNI, looked up again, and hands on the
// handshake read so far and everything after it, unread. A connection the
// gate's own sending will not make is cut off and recorded with the
// addresses the name was looked up to.
func (g *Gate) grantedPassthrough(c *peekConn, hello []byte, dst netip.AddrPort, sni string, ans decide.ConnectionAnswer) {
	defer func() { _ = c.Close() }()
	rec := g.base(audit.KindPassthrough, dst)
	rec.Name = sni
	rec.Treatment = "passthrough"
	rec.Grant = ans.Grant.ID
	rec.Reason = ans.Reason
	ctx := context.Background()
	if g.cfg.Direct == nil {
		rec.Error = "the gate has no sending of its own"
		g.refuseConn(rec, ans.Reason+"; the gate cannot send it itself")
		return
	}
	dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	up, err := g.cfg.Direct.Dial(dctx, sni, dst.Port())
	cancel()
	if err != nil {
		reported(rec, upstream.Report{}, err)
		rec.Error = fmt.Sprintf("the gate did not connect: %v", err)
		g.refuseConn(rec, ans.Reason)
		return
	}
	defer func() { _ = up.Close() }()
	reported(rec, up.Report, nil)
	rec.Verdict = audit.Allow
	if err := g.cfg.Log.Begin(ctx, rec); err != nil {
		g.cfg.Logger.Error("a passthrough could not be recorded, so it was not connected", "name", sni, "error", err)
		return
	}
	start := g.cfg.Now()
	defer func() {
		rec.Duration = g.cfg.Now().Sub(start)
		if err := g.cfg.Log.Finish(ctx, rec); err != nil {
			g.cfg.Logger.Error("a passthrough's record could not be finished", "id", rec.ID, "error", err)
		}
	}()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		rec.BytesUp, _ = io.Copy(up, io.MultiReader(bytes.NewReader(hello), c))
		closeWrite(up)
	}()
	rec.BytesDown, _ = io.Copy(c, up)
	closeWrite(c.Conn)
	wg.Wait()
}
