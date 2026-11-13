package gate

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync"

	"github.com/yuanying/natsumi-sentinel/internal/audit"
)

// passthrough connects c straight to its original destination without
// reading it. The record holds where, how much and how long.
func (g *Gate) passthrough(c net.Conn, dst netip.AddrPort, reason string) {
	defer func() { _ = c.Close() }()
	rec := g.base(audit.KindPassthrough, dst)
	rec.Treatment = "passthrough"
	rec.Verdict = audit.Allow
	rec.Reason = reason
	ctx := context.Background()
	if err := g.cfg.Log.Begin(ctx, rec); err != nil {
		g.cfg.Logger.Error("a passthrough could not be recorded, so it was not connected", "address", rec.Address, "error", err)
		return
	}
	start := g.cfg.Now()
	defer func() {
		rec.Duration = g.cfg.Now().Sub(start)
		if err := g.cfg.Log.Finish(ctx, rec); err != nil {
			g.cfg.Logger.Error("a passthrough's record could not be finished", "id", rec.ID, "error", err)
		}
	}()

	target := netip.AddrPortFrom(dst.Addr().Unmap(), dst.Port())
	up, err := g.cfg.Dial(ctx, "tcp", target.String())
	if err != nil {
		rec.Error = err.Error()
		return
	}
	defer func() { _ = up.Close() }()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		rec.BytesUp, _ = io.Copy(up, c)
		closeWrite(up)
	}()
	rec.BytesDown, _ = io.Copy(c, up)
	closeWrite(c)
	wg.Wait()
}

// closeWrite passes an end of stream on to the other side, keeping the
// other direction open.
func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = c.Close()
}
