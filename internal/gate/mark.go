package gate

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
)

// MarkHeader is on every response the gate makes itself, and the gate
// removes it from every response that comes from upstream, so a client can
// tell the gate's refusals from the upstream's (docs/adr/0004). Its value
// says which kind of answer it is. docs/gate-responses.md describes it.
const MarkHeader = "Natsumi-Sentinel"

const (
	// MarkDeny is a refusal: the request was not sent upstream.
	MarkDeny = "deny"
	// MarkAsk is a request held for the owner's answer: it was not sent
	// upstream, and goes through if made again once the owner allows it.
	MarkAsk = "ask"
	// MarkError is the gate failing to do its part: the request was not
	// sent, or not sent in full, because something in the gate failed.
	MarkError = "error"
)

// ApprovalHeader carries the id of the approval an asked request is held
// on, beside MarkAsk.
const ApprovalHeader = "Natsumi-Sentinel-Approval"

// writeGate writes one of the gate's own answers.
func writeGate(w http.ResponseWriter, status int, mark, text string) {
	h := w.Header()
	h.Set(MarkHeader, mark)
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, gateText(text))
}

// refusal is writeGate for a connection the HTTP server does not serve.
func refusal(req *http.Request, status int, mark, text string) *http.Response {
	body := gateText(text)
	resp := &http.Response{
		StatusCode:    status,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Request:       req,
		Header:        http.Header{},
		Body:          io.NopCloser(bytes.NewBufferString(body)),
		ContentLength: int64(len(body)),
		Close:         true,
	}
	resp.Header.Set(MarkHeader, mark)
	resp.Header.Set("Content-Type", "text/plain; charset=utf-8")
	resp.Header.Set("Cache-Control", "no-store")
	return resp
}

func gateText(text string) string {
	return fmt.Sprintf("natsumi-sentinel: %s\n", text)
}
