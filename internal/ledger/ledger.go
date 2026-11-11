// Package ledger is the gate's ledger of approvals and grants
// (docs/adr/0004): the requests held for the owner's answer, and what the
// owner allowed, for how much and for how long.
//
// It is a SQLite file of its own, on the gate's own volume beside the audit
// log. Every caller treats an error from it as "no grant": a request the
// ledger cannot vouch for does not go through.
package ledger

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	// Pure Go, as for the audit log.
	_ "modernc.org/sqlite"

	"github.com/yuanying/natsumi-sentinel/internal/audit"
	"github.com/yuanying/natsumi-sentinel/internal/routes"
)

// State is where an approval stands.
type State string

const (
	Pending State = "open"
	Allowed State = "allowed"
	Denied  State = "denied"
	// Expired is an approval nobody answered in time.
	Expired State = "expired"
)

// Kind is how an approval came about.
type Kind string

const (
	// KindRequest is a request the table said to ask about.
	KindRequest Kind = "request"
	// KindBeforehand is a list of operations the workspace asked for
	// before making the requests.
	KindBeforehand Kind = "beforehand"
)

// Scope is how far a grant reaches.
type Scope string

const (
	// ScopeOnce is one request: the one held, or one of the operations
	// asked for beforehand.
	ScopeOnce Scope = "once"
	// ScopeTimed is the operation on its target (a raw operation: its
	// destination, method and path) until the grant ends, if it does.
	ScopeTimed Scope = "timed"
)

// Facts are what the gate knows of one request, or of one operation asked
// for beforehand. They are all the approval shows: nothing the workspace
// wrote about why.
type Facts struct {
	Source      string `json:"-"`
	Destination string `json:"destination"`
	// Method, Path and Query are the request's; empty for an operation
	// asked for beforehand.
	Method string `json:"method,omitempty"`
	Path   string `json:"path,omitempty"`
	Query  string `json:"query,omitempty"`
	// Operation is empty for a raw operation.
	Operation string         `json:"operation,omitempty"`
	Params    []routes.Param `json:"params,omitempty"`
	// Target names the params that make the target.
	Target []string `json:"target,omitempty"`
	// TargetText is the target as the record writes it; Hold and Ask
	// fill it in.
	TargetText string      `json:"targetText,omitempty"`
	Body       *audit.Body `json:"body,omitempty"`
	// Fingerprint is the request's, for a grant of one request.
	Fingerprint string `json:"fingerprint,omitempty"`
	// Exact is true when the fingerprint covers the whole request, so a
	// grant of one request can be offered.
	Exact bool `json:"exact,omitempty"`
}

// TargetText writes the target as "name=value" pairs, in order.
func TargetText(params []routes.Param, target []string) string {
	var parts []string
	for _, name := range target {
		for _, p := range params {
			if p.Name == name {
				parts = append(parts, p.Name+"="+p.Value)
			}
		}
	}
	return strings.Join(parts, " ")
}

// Choice is one scope the owner can allow an approval for.
type Choice struct {
	ID    string `json:"id"`
	Scope Scope  `json:"scope"`
	// Seconds is how long the grant lasts: for a grant of one request,
	// how long it waits to be used. 0 on a timed grant is no end.
	Seconds int64  `json:"seconds"`
	Label   string `json:"label"`
}

// Approval is one request held, or one list asked for beforehand.
type Approval struct {
	ID      string    `json:"id"`
	Kind    Kind      `json:"kind"`
	State   State     `json:"state"`
	Source  string    `json:"source"`
	Created time.Time `json:"created"`
	Expires time.Time `json:"expires"`
	// Summary is a sentence the gate makes of the facts.
	Summary string   `json:"summary"`
	Items   []Facts  `json:"items"`
	Choices []Choice `json:"choices"`
	// Requests counts how many times the same request was held on it.
	Requests int `json:"requests"`

	Answered *time.Time `json:"answered,omitempty"`
	// Choice is the choice the owner allowed it with.
	Choice string   `json:"choice,omitempty"`
	Grants []string `json:"grants,omitempty"`

	fingerprint string
}

// Grant is what an allowed approval leaves in the ledger.
type Grant struct {
	ID       string     `json:"id"`
	Approval string     `json:"approval"`
	Source   string     `json:"source"`
	Scope    Scope      `json:"scope"`
	Created  time.Time  `json:"created"`
	Expires  *time.Time `json:"expires,omitempty"`
	Summary  string     `json:"summary"`

	Destination string `json:"destination"`
	Operation   string `json:"operation,omitempty"`
	Target      string `json:"target,omitempty"`
	Method      string `json:"method,omitempty"`
	Path        string `json:"path,omitempty"`

	fingerprint, opKey string
}

// Answer is the owner's answer to an approval.
type Answer struct {
	Allow bool
	// Choice is the ID of one of the approval's choices, when allowing.
	Choice string
}

var (
	ErrNotFound  = errors.New("no such approval or grant")
	ErrClosed    = errors.New("the approval is already closed")
	ErrBadChoice = errors.New("the approval does not offer that choice")
)

// EventType says what happened to an approval.
type EventType string

const (
	EventCreated EventType = "approval.created"
	EventClosed  EventType = "approval.closed"
)

// Event is told to subscribers when an approval is made or closed.
type Event struct {
	Type     EventType `json:"type"`
	Approval *Approval `json:"approval"`
}

// Ledger is the gate's ledger.
type Ledger struct {
	db  *sql.DB
	now func() time.Time

	mu   sync.Mutex
	subs map[chan Event]struct{}
}

const schemaVersion = 1

const schema = `
CREATE TABLE approvals (
	id TEXT PRIMARY KEY,
	state TEXT NOT NULL,
	source TEXT NOT NULL,
	fingerprint TEXT NOT NULL,
	created TEXT NOT NULL,
	expires TEXT NOT NULL,
	doc TEXT NOT NULL
);
CREATE INDEX approvals_open ON approvals (state, source, fingerprint);
CREATE TABLE grants (
	id TEXT PRIMARY KEY,
	source TEXT NOT NULL,
	scope TEXT NOT NULL,
	destination TEXT NOT NULL,
	operation TEXT NOT NULL,
	target TEXT NOT NULL,
	method TEXT NOT NULL,
	path TEXT NOT NULL,
	fingerprint TEXT NOT NULL,
	op_key TEXT NOT NULL,
	expires TEXT,
	created TEXT NOT NULL,
	doc TEXT NOT NULL
);
CREATE INDEX grants_match ON grants (source, destination, operation);
`

// Open opens the ledger at path, creating it if it does not exist. The
// directory must exist, as for the audit log.
func Open(path string, now func() time.Time) (*Ledger, error) {
	if _, err := os.Stat(filepath.Dir(path)); err != nil {
		return nil, fmt.Errorf("the ledger's directory: %w", err)
	}
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)")
	if err != nil {
		return nil, fmt.Errorf("open the ledger: %w", err)
	}
	db.SetMaxOpenConns(1)
	var v int
	if err := db.QueryRow("PRAGMA user_version").Scan(&v); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("read the ledger's version: %w", err)
	}
	switch v {
	case schemaVersion:
	case 0:
		if _, err := db.Exec(schema + fmt.Sprintf("PRAGMA user_version = %d;", schemaVersion)); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("create the ledger: %w", err)
		}
	default:
		_ = db.Close()
		return nil, fmt.Errorf("the ledger is version %d; this build knows %d", v, schemaVersion)
	}
	if now == nil {
		now = time.Now
	}
	return &Ledger{db: db, now: now, subs: map[chan Event]struct{}{}}, nil
}

// Close closes the file.
func (l *Ledger) Close() error { return l.db.Close() }

// Subscribe gives the events from now on. A subscriber that falls behind
// misses events; it can read the approvals again to catch up.
func (l *Ledger) Subscribe() (<-chan Event, func()) {
	ch := make(chan Event, 64)
	l.mu.Lock()
	l.subs[ch] = struct{}{}
	l.mu.Unlock()
	return ch, func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		if _, ok := l.subs[ch]; ok {
			delete(l.subs, ch)
			close(ch)
		}
	}
}

func (l *Ledger) tell(t EventType, a *Approval) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for ch := range l.subs {
		select {
		case ch <- Event{Type: t, Approval: a}:
		default:
		}
	}
}

// Lookup finds a grant that lets the request in f through, and uses it up
// if it is for one request. It returns nil when there is none.
func (l *Ledger) Lookup(ctx context.Context, f Facts) (*Grant, error) {
	now := formatTime(l.now())
	tx, err := l.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("read the ledger: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var (
		cond string
		args []any
	)
	if f.Exact && f.Fingerprint != "" {
		cond = "(scope = 'once' AND fingerprint = ?)"
		args = append(args, f.Fingerprint)
	}
	or := func(c string, a ...any) {
		if cond != "" {
			cond += " OR "
		}
		cond += c
		args = append(args, a...)
	}
	if f.Operation != "" {
		or("(scope = 'once' AND op_key = ?)", opKey(f))
		or("(scope = 'timed' AND operation = ? AND target = ?)", f.Operation, TargetText(f.Params, f.Target))
	} else {
		or("(scope = 'timed' AND operation = '' AND method = ? AND path = ?)", f.Method, f.Path)
	}
	// Grants for one request go first, so a timed grant is not what a
	// once grant is left over for.
	row := tx.QueryRowContext(ctx, `SELECT doc, scope, id FROM grants
		WHERE source = ? AND destination = ? AND (expires IS NULL OR expires > ?) AND (`+cond+`)
		ORDER BY scope = 'once' DESC, created LIMIT 1`,
		append([]any{f.Source, f.Destination, now}, args...)...)
	var doc, scope, id string
	if err := row.Scan(&doc, &scope, &id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("read the ledger: %w", err)
	}
	var g Grant
	if err := json.Unmarshal([]byte(doc), &g); err != nil {
		return nil, fmt.Errorf("read the ledger: %w", err)
	}
	if Scope(scope) == ScopeOnce {
		if _, err := tx.ExecContext(ctx, `DELETE FROM grants WHERE id = ?`, id); err != nil {
			return nil, fmt.Errorf("use a grant: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("use a grant: %w", err)
	}
	return &g, nil
}

// Hold makes an approval of the request in f, or, when the same request
// is already waiting, counts it on that one. created says which.
func (l *Ledger) Hold(ctx context.Context, f Facts, s routes.ApprovalSettings) (a *Approval, created bool, err error) {
	now := l.now()
	tx, err := l.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, fmt.Errorf("write the ledger: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var doc string
	err = tx.QueryRowContext(ctx, `SELECT doc FROM approvals WHERE state = 'open' AND source = ? AND fingerprint = ? AND expires > ? LIMIT 1`,
		f.Source, f.Fingerprint, formatTime(now)).Scan(&doc)
	switch {
	case err == nil:
		a = &Approval{}
		if err := json.Unmarshal([]byte(doc), a); err != nil {
			return nil, false, fmt.Errorf("read the ledger: %w", err)
		}
		a.Requests++
		if err := updateApproval(ctx, tx, a); err != nil {
			return nil, false, err
		}
		if err := tx.Commit(); err != nil {
			return nil, false, fmt.Errorf("write the ledger: %w", err)
		}
		return a, false, nil
	case !errors.Is(err, sql.ErrNoRows):
		return nil, false, fmt.Errorf("read the ledger: %w", err)
	}

	f.TargetText = TargetText(f.Params, f.Target)
	a = &Approval{
		ID:          newID("ap-"),
		Kind:        KindRequest,
		State:       Pending,
		Source:      f.Source,
		Created:     now,
		Expires:     now.Add(s.Pending),
		Items:       []Facts{f},
		Requests:    1,
		Summary:     summary(f),
		fingerprint: f.Fingerprint,
	}
	if f.Exact {
		a.Choices = append(a.Choices, onceChoice(s.Once))
	}
	for _, d := range s.Durations {
		a.Choices = append(a.Choices, timedChoice(f, d))
	}
	if err := insertApproval(ctx, tx, a); err != nil {
		return nil, false, err
	}
	if err := tx.Commit(); err != nil {
		return nil, false, fmt.Errorf("write the ledger: %w", err)
	}
	l.tell(EventCreated, a)
	return a, true, nil
}

// Ask makes an approval of operations asked for beforehand: a bundle of
// grants for one request each. The workspace does not choose the scope.
func (l *Ledger) Ask(ctx context.Context, source string, items []Facts, s routes.ApprovalSettings) (*Approval, error) {
	now := l.now()
	var parts []string
	for i := range items {
		items[i].Source = source
		items[i].TargetText = TargetText(items[i].Params, items[i].Target)
		parts = append(parts, operationText(items[i])+" on "+items[i].Destination)
	}
	a := &Approval{
		ID:       newID("ap-"),
		Kind:     KindBeforehand,
		State:    Pending,
		Source:   source,
		Created:  now,
		Expires:  now.Add(s.Pending),
		Items:    items,
		Requests: 1,
		Summary:  fmt.Sprintf("asked for beforehand, one request each: %s", strings.Join(parts, "; ")),
		Choices:  []Choice{onceChoice(s.Once)},
	}
	a.fingerprint = "beforehand:" + a.ID
	tx, err := l.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("write the ledger: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := insertApproval(ctx, tx, a); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("write the ledger: %w", err)
	}
	l.tell(EventCreated, a)
	return a, nil
}

// Answer closes an open approval with the owner's answer. record is called
// with the answered approval before it takes effect; when it fails, the
// answer is not taken (docs/adr/0006: an answer not recorded is not
// applied).
func (l *Ledger) Answer(ctx context.Context, id string, ans Answer, record func(*Approval) error) (*Approval, error) {
	now := l.now()
	tx, err := l.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("write the ledger: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	a, err := getApproval(ctx, tx, id)
	if err != nil {
		return nil, err
	}
	if a.State == Pending && !now.Before(a.Expires) {
		a.State = Expired
		if err := updateApproval(ctx, tx, a); err != nil {
			return nil, err
		}
		if err := tx.Commit(); err != nil {
			return nil, fmt.Errorf("write the ledger: %w", err)
		}
		l.tell(EventClosed, a)
		return nil, ErrClosed
	}
	if a.State != Pending {
		return nil, ErrClosed
	}
	a.Answered = &now
	if !ans.Allow {
		a.State = Denied
	} else {
		var choice *Choice
		for i := range a.Choices {
			if a.Choices[i].ID == ans.Choice {
				choice = &a.Choices[i]
			}
		}
		if choice == nil {
			return nil, ErrBadChoice
		}
		a.State = Allowed
		a.Choice = choice.ID
		for _, f := range a.Items {
			g := newGrant(a, f, *choice, now)
			if err := insertGrant(ctx, tx, g); err != nil {
				return nil, err
			}
			a.Grants = append(a.Grants, g.ID)
		}
	}
	if err := updateApproval(ctx, tx, a); err != nil {
		return nil, err
	}
	if record != nil {
		if err := record(a); err != nil {
			return nil, fmt.Errorf("the answer could not be recorded, so it was not taken: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("write the ledger: %w", err)
	}
	l.tell(EventClosed, a)
	return a, nil
}

// Get reads one approval.
func (l *Ledger) Get(ctx context.Context, id string) (*Approval, error) {
	return getApproval(ctx, l.db, id)
}

// Filter narrows Approvals. Zero fields do not narrow.
type Filter struct {
	Source string
	State  State
	// Limit is how many at most; 0 means 100.
	Limit int
}

// Approvals lists approvals: the open ones oldest first, the others
// newest first.
func (l *Ledger) Approvals(ctx context.Context, f Filter) ([]*Approval, error) {
	stmt := `SELECT doc FROM approvals WHERE 1 = 1`
	var args []any
	if f.Source != "" {
		stmt += ` AND source = ?`
		args = append(args, f.Source)
	}
	if f.State != "" {
		stmt += ` AND state = ?`
		args = append(args, string(f.State))
	}
	if f.State == Pending {
		stmt += ` ORDER BY created, id`
	} else {
		stmt += ` ORDER BY created DESC, id DESC`
	}
	limit := f.Limit
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	stmt += ` LIMIT ?`
	args = append(args, limit)
	rows, err := l.db.QueryContext(ctx, stmt, args...)
	if err != nil {
		return nil, fmt.Errorf("read the ledger: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*Approval
	for rows.Next() {
		var doc string
		if err := rows.Scan(&doc); err != nil {
			return nil, fmt.Errorf("read the ledger: %w", err)
		}
		a := &Approval{}
		if err := json.Unmarshal([]byte(doc), a); err != nil {
			return nil, fmt.Errorf("read the ledger: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// Grants lists the grants in effect, oldest first.
func (l *Ledger) Grants(ctx context.Context) ([]*Grant, error) {
	return l.grants(ctx, "")
}

// GrantsFor lists the grants in effect for one source.
func (l *Ledger) GrantsFor(ctx context.Context, source string) ([]*Grant, error) {
	return l.grants(ctx, source)
}

func (l *Ledger) grants(ctx context.Context, source string) ([]*Grant, error) {
	stmt := `SELECT doc FROM grants WHERE (expires IS NULL OR expires > ?)`
	args := []any{formatTime(l.now())}
	if source != "" {
		stmt += ` AND source = ?`
		args = append(args, source)
	}
	rows, err := l.db.QueryContext(ctx, stmt+` ORDER BY created, id`, args...)
	if err != nil {
		return nil, fmt.Errorf("read the ledger: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*Grant
	for rows.Next() {
		var doc string
		if err := rows.Scan(&doc); err != nil {
			return nil, fmt.Errorf("read the ledger: %w", err)
		}
		g := &Grant{}
		if err := json.Unmarshal([]byte(doc), g); err != nil {
			return nil, fmt.Errorf("read the ledger: %w", err)
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// Revoke takes a grant in effect out of the ledger. record is called before
// it takes effect, as for Answer.
func (l *Ledger) Revoke(ctx context.Context, id string, record func(*Grant) error) error {
	tx, err := l.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("write the ledger: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var doc string
	err = tx.QueryRowContext(ctx, `SELECT doc FROM grants WHERE id = ? AND (expires IS NULL OR expires > ?)`, id, formatTime(l.now())).Scan(&doc)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("read the ledger: %w", err)
	}
	g := &Grant{}
	if err := json.Unmarshal([]byte(doc), g); err != nil {
		return fmt.Errorf("read the ledger: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM grants WHERE id = ?`, id); err != nil {
		return fmt.Errorf("write the ledger: %w", err)
	}
	if record != nil {
		if err := record(g); err != nil {
			return fmt.Errorf("the revocation could not be recorded, so it was not taken: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("write the ledger: %w", err)
	}
	return nil
}

// Sweep closes the approvals whose time is up and deletes the grants that
// have ended.
func (l *Ledger) Sweep(ctx context.Context) error {
	now := formatTime(l.now())
	rows, err := l.db.QueryContext(ctx, `SELECT doc FROM approvals WHERE state = 'open' AND expires <= ?`, now)
	if err != nil {
		return fmt.Errorf("read the ledger: %w", err)
	}
	var expired []*Approval
	for rows.Next() {
		var doc string
		if err := rows.Scan(&doc); err != nil {
			_ = rows.Close()
			return fmt.Errorf("read the ledger: %w", err)
		}
		a := &Approval{}
		if err := json.Unmarshal([]byte(doc), a); err != nil {
			_ = rows.Close()
			return fmt.Errorf("read the ledger: %w", err)
		}
		expired = append(expired, a)
	}
	_ = rows.Close()
	for _, a := range expired {
		a.State = Expired
		if err := updateApproval(ctx, l.db, a); err != nil {
			return err
		}
		l.tell(EventClosed, a)
	}
	if _, err := l.db.ExecContext(ctx, `DELETE FROM grants WHERE expires IS NOT NULL AND expires <= ?`, now); err != nil {
		return fmt.Errorf("write the ledger: %w", err)
	}
	return nil
}

// RunSweeper sweeps every interval until ctx is done.
func (l *Ledger) RunSweeper(ctx context.Context, interval time.Duration, report func(error)) {
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			if err := l.Sweep(ctx); err != nil && report != nil {
				report(err)
			}
		}
	}
}

type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func insertApproval(ctx context.Context, db execer, a *Approval) error {
	doc, err := json.Marshal(a)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `INSERT INTO approvals (id, state, source, fingerprint, created, expires, doc) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		a.ID, string(a.State), a.Source, a.fingerprint, formatTime(a.Created), formatTime(a.Expires), string(doc))
	if err != nil {
		return fmt.Errorf("write the ledger: %w", err)
	}
	return nil
}

func updateApproval(ctx context.Context, db execer, a *Approval) error {
	doc, err := json.Marshal(a)
	if err != nil {
		return err
	}
	if _, err := db.ExecContext(ctx, `UPDATE approvals SET state = ?, doc = ? WHERE id = ?`, string(a.State), string(doc), a.ID); err != nil {
		return fmt.Errorf("write the ledger: %w", err)
	}
	return nil
}

func getApproval(ctx context.Context, db execer, id string) (*Approval, error) {
	var doc, fp string
	err := db.QueryRowContext(ctx, `SELECT doc, fingerprint FROM approvals WHERE id = ?`, id).Scan(&doc, &fp)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("read the ledger: %w", err)
	}
	a := &Approval{fingerprint: fp}
	if err := json.Unmarshal([]byte(doc), a); err != nil {
		return nil, fmt.Errorf("read the ledger: %w", err)
	}
	return a, nil
}

func newGrant(a *Approval, f Facts, c Choice, now time.Time) *Grant {
	g := &Grant{
		ID:          newID("gr-"),
		Approval:    a.ID,
		Source:      a.Source,
		Scope:       c.Scope,
		Created:     now,
		Destination: f.Destination,
		Operation:   f.Operation,
	}
	if c.Seconds > 0 {
		end := now.Add(time.Duration(c.Seconds) * time.Second)
		g.Expires = &end
	}
	switch {
	case c.Scope == ScopeOnce && a.Kind == KindBeforehand:
		g.opKey = opKey(f)
		g.Target = TargetText(f.Params, f.Target)
		g.Summary = "one request of " + operationText(f) + " on " + f.Destination
	case c.Scope == ScopeOnce:
		g.fingerprint = f.Fingerprint
		g.Target = TargetText(f.Params, f.Target)
		g.Method, g.Path = f.Method, f.Path
		g.Summary = "the one request " + requestText(f)
	case f.Operation != "":
		g.Target = TargetText(f.Params, f.Target)
		g.Summary = operationText(f) + " on " + f.Destination + " " + durationText(c.Seconds)
	default:
		g.Method, g.Path = f.Method, f.Path
		g.Summary = f.Method + " " + f.Path + " on " + f.Destination + " " + durationText(c.Seconds)
	}
	return g
}

func insertGrant(ctx context.Context, db execer, g *Grant) error {
	doc, err := json.Marshal(g)
	if err != nil {
		return err
	}
	var expires any
	if g.Expires != nil {
		expires = formatTime(*g.Expires)
	}
	_, err = db.ExecContext(ctx, `INSERT INTO grants (id, source, scope, destination, operation, target, method, path, fingerprint, op_key, expires, created, doc)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		g.ID, g.Source, string(g.Scope), g.Destination, g.Operation, g.Target, g.Method, g.Path, g.fingerprint, g.opKey, expires, formatTime(g.Created), string(doc))
	if err != nil {
		return fmt.Errorf("write the ledger: %w", err)
	}
	return nil
}

// opKey identifies a named operation with every one of its parameters: what
// a grant of one operation asked for beforehand is matched by.
func opKey(f Facts) string {
	h := sha256.New()
	for _, s := range []string{f.Destination, f.Operation} {
		_, _ = fmt.Fprintf(h, "%d:%s", len(s), s)
	}
	for _, p := range f.Params {
		_, _ = fmt.Fprintf(h, "%d:%s%d:%s", len(p.Name), p.Name, len(p.Value), p.Value)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func onceChoice(d time.Duration) Choice {
	return Choice{
		ID:      string(ScopeOnce),
		Scope:   ScopeOnce,
		Seconds: int64(d / time.Second),
		Label:   "this request only, once, if made again within " + routes.FormatDuration(d),
	}
}

func timedChoice(f Facts, d time.Duration) Choice {
	what := operationText(f) + " on " + f.Destination
	if f.Operation == "" {
		what = f.Method + " " + f.Path + " on " + f.Destination
	}
	return Choice{
		ID:      routes.FormatDuration(d),
		Scope:   ScopeTimed,
		Seconds: int64(d / time.Second),
		Label:   what + " " + durationText(int64(d/time.Second)),
	}
}

func durationText(seconds int64) string {
	if seconds == 0 {
		return "with no end"
	}
	return "for " + routes.FormatDuration(time.Duration(seconds)*time.Second)
}

func operationText(f Facts) string {
	if t := TargetText(f.Params, f.Target); t != "" {
		return f.Operation + " (" + t + ")"
	}
	return f.Operation
}

func requestText(f Facts) string {
	s := f.Method + " https://" + f.Destination + f.Path
	if f.Query != "" {
		s += "?" + f.Query
	}
	return s
}

func summary(f Facts) string {
	s := requestText(f)
	if f.Operation != "" {
		s += ", the operation " + operationText(f)
		var args []string
		for _, p := range f.Params {
			args = append(args, p.Name+"="+p.Value)
		}
		if len(args) > 0 {
			s += " with " + strings.Join(args, " ")
		}
	} else {
		s += ", which no rule names"
	}
	if f.Body != nil {
		switch {
		case f.Body.Binary:
			s += fmt.Sprintf("; a body of %d bytes that is not text", f.Body.Size)
		case f.Body.Truncated:
			s += fmt.Sprintf("; a body of %d bytes, of which the start is shown", f.Body.Size)
		default:
			s += fmt.Sprintf("; a body of %d bytes", f.Body.Size)
		}
	}
	return s
}

var idEncoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

func newID(prefix string) string {
	b := make([]byte, 10)
	_, _ = rand.Read(b)
	return prefix + idEncoding.EncodeToString(b)
}

const timeFormat = "2006-01-02T15:04:05.000000000Z07:00"

func formatTime(t time.Time) string { return t.UTC().Format(timeFormat) }
