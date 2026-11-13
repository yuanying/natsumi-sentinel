package gate

import (
	"errors"
	"net/http"
	"net/netip"

	"github.com/yuanying/natsumi-sentinel/internal/audit"
	"github.com/yuanying/natsumi-sentinel/internal/upstream"
)

// This file is what the gate does with what a destination grant lets
// through (docs/adr/0008, docs/destination-grants.md "接続と要求"): the
// gate sends it upstream itself, with its own sending, to the name looked
// up again.

// DirectSender is the gate's own sending: *upstream.Sender is one.
type DirectSender interface {
	http.RoundTripper
}

// MarkInsidePublic is put at the end of the reason of a record of an
// inside name that was connected to a public address (docs/adr/0008: the
// inside name's DNS may have been taken to point outside).
const MarkInsidePublic = "; an inside name connected to a public address"

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
