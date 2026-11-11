// Package approvals serves the gate's two doors to its ledger
// (docs/adr/0004, docs/approvals-api.md):
//
//   - Owner is for natsumi's server, on a Unix socket only the server's UID
//     may use: the approvals and their answers, the grants and their
//     revocation, a stream of events, and the audit records.
//   - Agent is for the workspace, on the gate's own address: its own
//     approvals, grants and recent refusals, and asking beforehand for
//     concrete operations. It cannot answer anything.
//
// Every answer, revocation and request made beforehand is recorded before
// it takes effect (docs/adr/0006).
package approvals

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/yuanying/natsumi-sentinel/internal/audit"
	"github.com/yuanying/natsumi-sentinel/internal/ledger"
	"github.com/yuanying/natsumi-sentinel/internal/routes"
)

// Records is the audit log as the doors use it.
type Records interface {
	Write(ctx context.Context, rec *audit.Record) error
	List(ctx context.Context, q audit.Query) ([]*audit.Record, error)
	Get(ctx context.Context, id int64) (*audit.Record, error)
}

// OwnerConfig is what Owner needs.
type OwnerConfig struct {
	Ledger *ledger.Ledger
	Log    Records
	// Ping is how often the event stream says it is alive. Defaults to
	// 30s.
	Ping time.Duration
	Now  func() time.Time
	// Answered is told each answer once it has taken effect, and Revoked
	// each revocation with its time (docs/notices.md). Either may be nil.
	Answered func(*ledger.Approval)
	Revoked  func(g *ledger.Grant, at time.Time)
}

// maxBody bounds what the doors read of a request body.
const maxBody = 1 << 20

// Owner is the door for natsumi's server.
func Owner(cfg OwnerConfig) http.Handler {
	if cfg.Ping == 0 {
		cfg.Ping = 30 * time.Second
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	o := &owner{cfg: cfg}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/approvals", o.listApprovals)
	mux.HandleFunc("GET /v1/approvals/{id}", o.getApproval)
	mux.HandleFunc("POST /v1/approvals/{id}/answer", o.answer)
	mux.HandleFunc("GET /v1/grants", o.listGrants)
	mux.HandleFunc("DELETE /v1/grants/{id}", o.revoke)
	mux.HandleFunc("GET /v1/events", o.events)
	mux.HandleFunc("GET /v1/records", o.listRecords)
	mux.HandleFunc("GET /v1/records/{id}", o.getRecord)
	mux.HandleFunc("/", notFound)
	return mux
}

type owner struct{ cfg OwnerConfig }

var states = map[string]ledger.State{
	"":        ledger.Pending,
	"open":    ledger.Pending,
	"allowed": ledger.Allowed,
	"denied":  ledger.Denied,
	"expired": ledger.Expired,
	"all":     "",
}

func (o *owner) listApprovals(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	st, ok := states[q.Get("state")]
	if !ok {
		writeError(w, http.StatusBadRequest, "state is one of open, allowed, denied, expired and all")
		return
	}
	limit, err := intParam(q.Get("limit"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "limit: "+err.Error())
		return
	}
	list, err := o.cfg.Ledger.Approvals(r.Context(), ledger.Filter{State: st, Source: q.Get("source"), Limit: int(limit)})
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "the ledger could not be read")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"approvals": nonNil(list)})
}

func (o *owner) getApproval(w http.ResponseWriter, r *http.Request) {
	a, err := o.cfg.Ledger.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		writeLedgerError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, a)
}

type answerBody struct {
	Answer string `json:"answer"`
	Choice string `json:"choice"`
}

func (o *owner) answer(w http.ResponseWriter, r *http.Request) {
	var body answerBody
	if err := decode(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var ans ledger.Answer
	switch body.Answer {
	case "allow":
		if body.Choice == "" {
			writeError(w, http.StatusBadRequest, "choice: allowing takes one of the approval's choices")
			return
		}
		ans = ledger.Answer{Allow: true, Choice: body.Choice}
	case "deny":
		ans = ledger.Answer{}
	default:
		writeError(w, http.StatusBadRequest, "answer is allow or deny")
		return
	}
	a, err := o.cfg.Ledger.Answer(r.Context(), r.PathValue("id"), ans, func(a *ledger.Approval) error {
		return o.cfg.Log.Write(context.WithoutCancel(r.Context()), answerRecord(a, o.cfg.Now()))
	})
	if err != nil {
		writeLedgerError(w, err)
		return
	}
	if o.cfg.Answered != nil {
		o.cfg.Answered(a)
	}
	writeJSON(w, http.StatusOK, a)
}

// answerRecord is the record of the owner's answer (docs/adr/0006).
func answerRecord(a *ledger.Approval, now time.Time) *audit.Record {
	rec := &audit.Record{Time: now, Source: a.Source, Kind: audit.KindAnswer, Approval: a.ID}
	if len(a.Items) > 0 {
		f := a.Items[0]
		rec.Name, rec.Operation, rec.Target = f.Destination, f.Operation, f.TargetText
		rec.Method, rec.Path, rec.Query = f.Method, f.Path, f.Query
	}
	if a.State == ledger.Allowed {
		rec.Verdict = audit.Allow
		rec.Grant = strings.Join(a.Grants, " ")
		label := a.Choice
		for _, c := range a.Choices {
			if c.ID == a.Choice {
				label = c.ID + ": " + c.Label
			}
		}
		rec.Reason = fmt.Sprintf("the owner allowed %s with the choice %s", a.ID, label)
	} else {
		rec.Verdict = audit.Deny
		rec.Reason = fmt.Sprintf("the owner denied %s", a.ID)
	}
	return rec
}

func (o *owner) listGrants(w http.ResponseWriter, r *http.Request) {
	list, err := o.cfg.Ledger.Grants(r.Context())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "the ledger could not be read")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"grants": nonNil(list)})
}

func (o *owner) revoke(w http.ResponseWriter, r *http.Request) {
	var (
		revoked *ledger.Grant
		at      time.Time
	)
	err := o.cfg.Ledger.Revoke(r.Context(), r.PathValue("id"), func(g *ledger.Grant) error {
		revoked, at = g, o.cfg.Now()
		return o.cfg.Log.Write(context.WithoutCancel(r.Context()), &audit.Record{
			Time: at, Source: g.Source, Kind: audit.KindAnswer, Verdict: audit.Deny,
			Name: g.Destination, Operation: g.Operation, Target: g.Target, Method: g.Method, Path: g.Path,
			Approval: g.Approval, Grant: g.ID,
			Reason: fmt.Sprintf("the owner revoked %s (%s)", g.ID, g.Summary),
		})
	})
	if err != nil {
		writeLedgerError(w, err)
		return
	}
	if o.cfg.Revoked != nil {
		o.cfg.Revoked(revoked, at)
	}
	writeJSON(w, http.StatusOK, map[string]any{"revoked": revoked})
}

func (o *owner) events(w http.ResponseWriter, r *http.Request) {
	events, cancel := o.cfg.Ledger.Subscribe()
	defer cancel()
	rc := http.NewResponseController(w)
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	enc := json.NewEncoder(w)
	send := func(v any) bool {
		if err := enc.Encode(v); err != nil {
			return false
		}
		return rc.Flush() == nil
	}
	if !send(map[string]string{"type": "hello"}) {
		return
	}
	tick := time.NewTicker(o.cfg.Ping)
	defer tick.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case e, ok := <-events:
			if !ok || !send(e) {
				return
			}
		case <-tick.C:
			if !send(map[string]string{"type": "ping"}) {
				return
			}
		}
	}
}

func (o *owner) listRecords(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	query := audit.Query{Source: q.Get("source"), Kind: audit.Kind(q.Get("kind"))}
	for _, v := range q["verdict"] {
		query.Verdicts = append(query.Verdicts, audit.Verdict(v))
	}
	var err error
	if query.Before, err = intParam(q.Get("before")); err != nil {
		writeError(w, http.StatusBadRequest, "before: "+err.Error())
		return
	}
	limit, err := intParam(q.Get("limit"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "limit: "+err.Error())
		return
	}
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	query.Limit = int(limit) + 1
	recs, err := o.cfg.Log.List(r.Context(), query)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "the audit log could not be read")
		return
	}
	out := map[string]any{"records": nonNil(recs)}
	if len(recs) > int(limit) {
		recs = recs[:limit]
		out["records"] = recs
		out["next"] = recs[len(recs)-1].ID
	}
	writeJSON(w, http.StatusOK, out)
}

func (o *owner) getRecord(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusNotFound, "no such record")
		return
	}
	rec, err := o.cfg.Log.Get(r.Context(), id)
	if errors.Is(err, audit.ErrNotFound) {
		writeError(w, http.StatusNotFound, "no such record")
		return
	}
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "the audit log could not be read")
		return
	}
	writeJSON(w, http.StatusOK, rec)
}

// AgentConfig is what Agent needs.
type AgentConfig struct {
	// Source is the listener the workspace's connections come in on; the
	// workspace reads only what belongs to it.
	Source string
	Ledger *ledger.Ledger
	Log    Records
	Routes func() *routes.Table
	// Refusals is how far back the recent refusals go. Defaults to a day.
	Refusals time.Duration
	Now      func() time.Time
}

// maxItems bounds one request beforehand.
const maxItems = 50

// Agent is the door for the workspace.
func Agent(cfg AgentConfig) http.Handler {
	if cfg.Refusals == 0 {
		cfg.Refusals = 24 * time.Hour
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	a := &agent{cfg: cfg}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", a.status)
	mux.HandleFunc("GET /v1/approvals/{id}", a.getApproval)
	mux.HandleFunc("POST /v1/approvals", a.ask)
	mux.HandleFunc("/", notFound)
	return mux
}

type agent struct{ cfg AgentConfig }

// refusal is what the workspace reads of a request the gate refused or
// held.
type refusal struct {
	Time      time.Time     `json:"time"`
	Verdict   audit.Verdict `json:"verdict"`
	Name      string        `json:"name"`
	Method    string        `json:"method,omitempty"`
	Path      string        `json:"path,omitempty"`
	Operation string        `json:"operation,omitempty"`
	Target    string        `json:"target,omitempty"`
	Approval  string        `json:"approval,omitempty"`
	Reason    string        `json:"reason"`
}

func (a *agent) status(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pending, err := a.cfg.Ledger.Approvals(ctx, ledger.Filter{Source: a.cfg.Source, State: ledger.Pending})
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "the ledger could not be read")
		return
	}
	grants, err := a.cfg.Ledger.GrantsFor(ctx, a.cfg.Source)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "the ledger could not be read")
		return
	}
	recs, err := a.cfg.Log.List(ctx, audit.Query{
		Source: a.cfg.Source, Kind: audit.KindHTTP, Verdicts: []audit.Verdict{audit.Deny, audit.Ask},
		Since: a.cfg.Now().Add(-a.cfg.Refusals), Limit: 20,
	})
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "the audit log could not be read")
		return
	}
	refused := []refusal{}
	for _, rec := range recs {
		refused = append(refused, refusal{
			Time: rec.Time, Verdict: rec.Verdict, Name: rec.Name, Method: rec.Method, Path: rec.Path,
			Operation: rec.Operation, Target: rec.Target, Approval: rec.Approval, Reason: rec.Reason,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"approvals": nonNil(pending),
		"grants":    nonNil(grants),
		"refused":   refused,
	})
}

func (a *agent) getApproval(w http.ResponseWriter, r *http.Request) {
	ap, err := a.cfg.Ledger.Get(r.Context(), r.PathValue("id"))
	if err == nil && ap.Source != a.cfg.Source {
		err = ledger.ErrNotFound
	}
	if err != nil {
		writeLedgerError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, ap)
}

type askItem struct {
	Destination string            `json:"destination"`
	Operation   string            `json:"operation"`
	Params      map[string]string `json:"params"`
}

type askBody struct {
	Items []askItem `json:"items"`
}

// errDenied is an operation the table denies: no approval can let it
// through, so none is made.
var errDenied = errors.New("denied")

func (a *agent) ask(w http.ResponseWriter, r *http.Request) {
	var body askBody
	if err := decode(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(body.Items) == 0 || len(body.Items) > maxItems {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("items: from 1 to %d operations", maxItems))
		return
	}
	table := a.cfg.Routes()
	var facts []ledger.Facts
	for i, it := range body.Items {
		f, err := itemFacts(table, it)
		if err != nil {
			status := http.StatusBadRequest
			if errors.Is(err, errDenied) {
				status = http.StatusForbidden
			}
			writeError(w, status, fmt.Sprintf("items[%d]: %v", i, err))
			return
		}
		facts = append(facts, f)
	}
	ap, err := a.cfg.Ledger.Ask(r.Context(), a.cfg.Source, facts, table.Approvals(), func(ap *ledger.Approval) error {
		f := ap.Items[0]
		return a.cfg.Log.Write(context.WithoutCancel(r.Context()), &audit.Record{
			Time: a.cfg.Now(), Source: a.cfg.Source, Kind: audit.KindAgent, Verdict: audit.Ask,
			Name: f.Destination, Operation: f.Operation, Target: f.TargetText, Approval: ap.ID,
			Method: r.Method, Path: r.URL.Path,
			Reason: "the workspace asked beforehand: " + ap.Summary,
		})
	})
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "the request could not be recorded or kept, so no approval was made")
		return
	}
	writeJSON(w, http.StatusCreated, ap)
}

// itemFacts checks one operation asked for beforehand against the table:
// it has to be one a rule names on an open destination, with exactly the
// rule's parameters, and one the table asks about.
func itemFacts(table *routes.Table, it askItem) (ledger.Facts, error) {
	d, ok := table.Lookup(it.Destination, 443)
	if !ok || d.Treatment != routes.Open {
		return ledger.Facts{}, fmt.Errorf("%q is not an open destination", it.Destination)
	}
	names, target, ok := d.RuleParams(it.Operation)
	if !ok {
		return ledger.Facts{}, fmt.Errorf("no rule of %s names the operation %q", d.Name, it.Operation)
	}
	switch d.ActionFor(it.Operation) {
	case routes.Deny:
		return ledger.Facts{}, fmt.Errorf("%w: the table denies %s; to change it, the owner edits the table", errDenied, it.Operation)
	case routes.Allow:
		return ledger.Facts{}, fmt.Errorf("the table already allows %s; there is nothing to ask", it.Operation)
	}
	for k := range it.Params {
		if !slices.Contains(names, k) {
			return ledger.Facts{}, fmt.Errorf("params: %s takes no %q", it.Operation, k)
		}
	}
	var params []routes.Param
	for _, n := range names {
		v := it.Params[n]
		if v == "" {
			return ledger.Facts{}, fmt.Errorf("params: %s needs %q", it.Operation, n)
		}
		params = append(params, routes.Param{Name: n, Value: v})
	}
	return ledger.Facts{Destination: d.Name, Operation: it.Operation, Params: params, Target: target}, nil
}

func notFound(w http.ResponseWriter, _ *http.Request) {
	writeError(w, http.StatusNotFound, "no such path")
}

func decode(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("the body is not the JSON this takes: %v", err)
	}
	return nil
}

func intParam(s string) (int64, error) {
	if s == "" {
		return 0, nil
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("%q is not a whole number", s)
	}
	return n, nil
}

func writeLedgerError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ledger.ErrNotFound):
		writeError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, ledger.ErrClosed):
		writeError(w, http.StatusConflict, err.Error())
	case errors.Is(err, ledger.ErrBadChoice):
		writeError(w, http.StatusBadRequest, err.Error())
	default:
		writeError(w, http.StatusServiceUnavailable, "the ledger or the audit log could not be used, so nothing was changed")
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
