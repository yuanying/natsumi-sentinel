package ledger

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/yuanying/natsumi-sentinel/internal/domains"
	"github.com/yuanying/natsumi-sentinel/internal/routes"
)

// This file is the ledger's part of the destination grants
// (docs/adr/0008, docs/destination-grants.md): grants for names not in the
// routing table, the approvals of names the workspace asked for
// beforehand, and the names the gate refused and remembers for the owner.

// GrantKind tells an operation grant from a destination grant.
type GrantKind string

const (
	GrantOperation   GrantKind = "operation"
	GrantDestination GrantKind = "destination"
)

// Unit is how wide a destination grant is.
type Unit string

const (
	// UnitName is the name only.
	UnitName Unit = "name"
	// UnitDomain is the domain and every name under it.
	UnitDomain Unit = "domain"
)

// Handling is what the gate does with a granted destination's
// connections.
type Handling string

const (
	// Inspect terminates TLS with the gate's CA and reads each request.
	Inspect Handling = "inspect"
	// Passthrough connects the TLS of the workspace straight through.
	Passthrough Handling = "passthrough"
)

// Access is what of the requests on an inspected destination goes
// through without asking.
type Access string

const (
	// Read lets reads through; a write is asked about as a raw
	// operation.
	Read Access = "read"
	// ReadWrite lets reads and writes through.
	ReadWrite Access = "readwrite"
)

// Option is one choice of an option.
type Option struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

// Options are the choices of a destination grant beyond its time, the
// first of each the default.
type Options struct {
	Unit     []Option `json:"unit"`
	Handling []Option `json:"handling"`
	Access   []Option `json:"access"`
}

// OptionAnswer is the options chosen, by their ids. An empty id is the
// default.
type OptionAnswer struct {
	Unit     string `json:"unit,omitempty"`
	Handling string `json:"handling,omitempty"`
	Access   string `json:"access,omitempty"`
}

// The names of the facts on an item of an approval of destinations.
const (
	FactInside        = "inside"
	FactDomain        = "registrableDomain"
	FactRefusedCount  = "refusedCount"
	FactRefusedLast   = "refusedLast"
	FactDomainDefault = "registrableDomainByDefaultRule"
)

// How many refused names are kept for one source, and for how long after
// they were last refused, unless SetRefusedLimits says otherwise
// (docs/destination-grants.md "断った名前の覚え").
const (
	RefusedMax = 1000
	RefusedAge = 30 * 24 * time.Hour
)

// SetRefusedLimits changes how many refused names are kept for one source,
// and for how long.
func (l *Ledger) SetRefusedLimits(max int, age time.Duration) {
	l.refusedMax, l.refusedAge = max, age
}

// DestinationFacts are the facts of an item asking for name: whether it is
// an inside name, its registrable domain, and how often and when it was
// last refused, if it is remembered. They are shown, never matched.
func DestinationFacts(name string, inside bool, r *RefusedName) Facts {
	f := Facts{Destination: name, Facts: []routes.Param{{Name: FactInside, Value: strconv.FormatBool(inside)}}}
	if dom, byDefault, ok := domains.Registrable(name); ok {
		f.Facts = append(f.Facts, routes.Param{Name: FactDomain, Value: dom})
		if byDefault {
			f.Facts = append(f.Facts, routes.Param{Name: FactDomainDefault, Value: "true"})
		}
	}
	if r != nil {
		f.Facts = append(f.Facts,
			routes.Param{Name: FactRefusedCount, Value: strconv.FormatInt(r.Count, 10)},
			routes.Param{Name: FactRefusedLast, Value: r.Last.UTC().Format(time.RFC3339)})
	}
	return f
}

func fact(f Facts, name string) string {
	for _, p := range f.Facts {
		if p.Name == name {
			return p.Value
		}
	}
	return ""
}

// DestinationOptions are the options offered for a grant of names: the
// name only, or one of the domains that cover every one of them up to
// their registrable domain; opened or passed through; reads only or reads
// and writes.
func DestinationOptions(names []string) *Options {
	nameLabel := "this name only: " + strings.Join(names, ", ")
	if len(names) > 1 {
		nameLabel = "each name only: " + strings.Join(names, ", ")
	}
	o := &Options{Unit: []Option{{ID: string(UnitName), Label: nameLabel}}}
	for _, d := range commonWidths(names) {
		o.Unit = append(o.Unit, Option{ID: "domain:" + d, Label: domainText(d)})
	}
	o.Handling = []Option{
		{ID: string(Inspect), Label: handlingText(Inspect)},
		{ID: string(Passthrough), Label: handlingText(Passthrough)},
	}
	o.Access = []Option{
		{ID: string(Read), Label: accessText(Read)},
		{ID: string(ReadWrite), Label: accessText(ReadWrite)},
	}
	return o
}

// commonWidths are the domains every one of names can be widened to,
// nearest first.
func commonWidths(names []string) []string {
	if len(names) == 0 {
		return nil
	}
	var out []string
	for _, d := range domains.Widths(names[0]) {
		all := true
		for _, n := range names[1:] {
			if !contains(domains.Widths(n), d) {
				all = false
			}
		}
		if all {
			out = append(out, d)
		}
	}
	return out
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func domainText(d string) string {
	s := d + " itself and every name under it"
	if _, byDefault, _ := domains.Registrable(d); byDefault {
		suffix := d[strings.LastIndexByte(d, '.')+1:]
		s += fmt.Sprintf(" (%s is in no rule of the public suffix list: the list's default rule ends the width here, and the gate sets no narrower limit)", suffix)
	}
	return s
}

func handlingText(h Handling) string {
	if h == Passthrough {
		return "passed through unopened: reads and writes both go through, and what is in them is not seen"
	}
	return "opened: the gate terminates TLS and reads and records each request"
}

func accessText(a Access) string {
	if a == ReadWrite {
		return "reads and writes go through without asking"
	}
	return "reads only: each write is asked about"
}

// destinationChoices are the times a destination grant can be given for:
// the durations of the settings, never once (docs/adr/0008: one visit is
// many requests).
func destinationChoices(s routes.ApprovalSettings) []Choice {
	var out []Choice
	for _, d := range s.Durations {
		secs := int64(d / time.Second)
		out = append(out, Choice{ID: routes.FormatDuration(d), Scope: ScopeTimed, Seconds: secs, Label: "the destination as chosen below, " + durationText(secs)})
	}
	return out
}

// chosen is a destination grant's shape, from the options of an approval
// or a refused name.
type chosen struct {
	unit     Unit
	domain   string
	handling Handling
	access   Access
	answer   OptionAnswer
}

// choose checks ans against o, and takes the defaults for what it leaves
// out.
func choose(o *Options, ans *OptionAnswer) (chosen, error) {
	var a OptionAnswer
	if ans != nil {
		a = *ans
	}
	pick := func(opts []Option, id string) (string, error) {
		if id == "" {
			return opts[0].ID, nil
		}
		for _, op := range opts {
			if op.ID == id {
				return id, nil
			}
		}
		return "", ErrBadChoice
	}
	var (
		c   chosen
		err error
	)
	if c.answer.Unit, err = pick(o.Unit, a.Unit); err != nil {
		return chosen{}, err
	}
	if c.answer.Handling, err = pick(o.Handling, a.Handling); err != nil {
		return chosen{}, err
	}
	if c.answer.Access, err = pick(o.Access, a.Access); err != nil {
		return chosen{}, err
	}
	c.unit = UnitName
	if d, ok := strings.CutPrefix(c.answer.Unit, "domain:"); ok {
		c.unit, c.domain = UnitDomain, d
	}
	c.handling = Handling(c.answer.Handling)
	c.access = Access(c.answer.Access)
	if c.handling == Passthrough {
		// A passthrough cannot tell reads from writes.
		c.access, c.answer.Access = "", ""
	}
	return c, nil
}

func newDestinationGrant(approval, source string, f Facts, c chosen, choice Choice, now time.Time) *Grant {
	g := &Grant{
		ID:       newID("gr-"),
		Kind:     GrantDestination,
		Approval: approval,
		Source:   source,
		Scope:    ScopeTimed,
		Created:  now,
		Name:     f.Destination,
		Unit:     c.unit,
		Handling: c.handling,
		Access:   c.access,
	}
	if c.unit == UnitDomain {
		g.Name = c.domain
	}
	if choice.Seconds > 0 {
		end := now.Add(time.Duration(choice.Seconds) * time.Second)
		g.Expires = &end
	}
	what := "the name " + g.Name + " only"
	if g.Unit == UnitDomain {
		what = domainText(g.Name)
	}
	parts := []string{what, handlingText(g.Handling)}
	if g.Access != "" {
		parts = append(parts, accessText(g.Access))
	}
	parts = append(parts, durationText(choice.Seconds))
	g.Summary = strings.Join(parts, "; ")
	if fact(f, FactInside) == "true" {
		g.Summary += "; an inside name"
	}
	return g
}

// AskDestinations makes an approval of names not in the routing table the
// workspace asked for beforehand. The caller has checked that each may be
// granted. record is called with the approval before it is kept, as for
// Ask.
func (l *Ledger) AskDestinations(ctx context.Context, source string, items []Facts, s routes.ApprovalSettings, record func(*Approval) error) (*Approval, error) {
	now := l.now()
	var names []string
	for i := range items {
		items[i].Source = source
		names = append(names, items[i].Destination)
	}
	summary := "asked for beforehand, destinations not in the routing table: " + strings.Join(names, ", ")
	var inside []string
	for _, f := range items {
		if fact(f, FactInside) == "true" {
			inside = append(inside, f.Destination)
		}
	}
	if len(inside) > 0 {
		summary += "; inside names: " + strings.Join(inside, ", ")
	}
	a := &Approval{
		ID:       newID("ap-"),
		Kind:     KindDestination,
		State:    Pending,
		Source:   source,
		Created:  now,
		Expires:  now.Add(s.Pending),
		Items:    items,
		Requests: 1,
		Summary:  summary,
		Choices:  destinationChoices(s),
		Options:  DestinationOptions(names),
	}
	a.fingerprint = "destination:" + a.ID
	tx, err := l.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("write the ledger: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := insertApproval(ctx, tx, a); err != nil {
		return nil, err
	}
	if record != nil {
		if err := record(a); err != nil {
			return nil, fmt.Errorf("the request could not be recorded, so it was not taken: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("write the ledger: %w", err)
	}
	l.tell(EventCreated, a)
	return a, nil
}

// allowDestinations allows an approval of destinations: a grant for each
// item, in the shape the options chosen give.
func (l *Ledger) allowDestinations(ctx context.Context, tx *sql.Tx, a *Approval, ans Answer, now time.Time) error {
	var choice *Choice
	for i := range a.Choices {
		if a.Choices[i].ID == ans.Choice {
			choice = &a.Choices[i]
		}
	}
	if choice == nil || a.Options == nil {
		return ErrBadChoice
	}
	c, err := choose(a.Options, ans.Options)
	if err != nil {
		return err
	}
	a.State = Allowed
	a.Choice = choice.ID
	a.Chosen = &c.answer
	for _, f := range a.Items {
		g := newDestinationGrant(a.ID, a.Source, f, c, *choice, now)
		if err := insertGrant(ctx, tx, g); err != nil {
			return err
		}
		if err := forgetCovered(ctx, tx, g); err != nil {
			return err
		}
		a.Grants = append(a.Grants, g.ID)
	}
	return nil
}

// LookupDestination finds the destination grant that covers name for
// source, or nil. Of several, an opened one goes before a passthrough, one
// for reads and writes before one for reads, one for the name before one
// for a domain, and an older before a newer (docs/destination-grants.md
// "どの許しが当たるか"). Whether the routing table has the name is the
// caller's to check first.
func (l *Ledger) LookupDestination(ctx context.Context, source, name string) (*Grant, error) {
	suffixes := domains.Suffixes(name)
	marks := strings.TrimSuffix(strings.Repeat("?, ", len(suffixes)), ", ")
	args := []any{source, formatTime(l.now()), name}
	for _, s := range suffixes {
		args = append(args, s)
	}
	var doc string
	err := l.db.QueryRowContext(ctx, `SELECT doc FROM grants
		WHERE kind = 'destination' AND source = ? AND (expires IS NULL OR expires > ?)
		AND ((unit = 'name' AND name = ?) OR (unit = 'domain' AND name IN (`+marks+`)))
		ORDER BY handling = 'inspect' DESC, access = 'readwrite' DESC, unit = 'name' DESC, created, id LIMIT 1`, args...).Scan(&doc)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read the ledger: %w", err)
	}
	return decodeGrant(doc)
}

// GrantShape is how a destination grant is handled, for counting them.
type GrantShape struct {
	Handling Handling
	Access   Access
}

// CountDestinationGrants counts the destination grants in effect by their
// handling and access.
func (l *Ledger) CountDestinationGrants(ctx context.Context) (map[GrantShape]int, error) {
	rows, err := l.db.QueryContext(ctx, `SELECT handling, access, count(*) FROM grants
		WHERE kind = 'destination' AND (expires IS NULL OR expires > ?) GROUP BY handling, access`, formatTime(l.now()))
	if err != nil {
		return nil, fmt.Errorf("read the ledger: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[GrantShape]int{}
	for rows.Next() {
		var (
			h, a string
			n    int
		)
		if err := rows.Scan(&h, &a, &n); err != nil {
			return nil, fmt.Errorf("read the ledger: %w", err)
		}
		out[GrantShape{Handling: Handling(h), Access: Access(a)}] = n
	}
	return out, rows.Err()
}

// RefusedName is a name the gate refused in name resolution, as it is
// remembered for the owner. Nothing the gate looked up is kept with it:
// the name was never looked up.
type RefusedName struct {
	Source string
	Name   string
	// Domain is the name's registrable domain; empty when it has none.
	Domain string
	First  time.Time
	Last   time.Time
	Count  int64
}

// RememberRefused keeps name as refused for source now, or counts it again
// if it is kept. The oldest names beyond the limit are dropped; dropped
// says how many. Which names are worth keeping is the caller's to decide.
func (l *Ledger) RememberRefused(ctx context.Context, source, name string) (dropped int, err error) {
	now := formatTime(l.now())
	dom, _, _ := domains.Registrable(name)
	tx, err := l.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("write the ledger: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `INSERT INTO refused_names (source, name, domain, first, last, count) VALUES (?, ?, ?, ?, ?, 1)
		ON CONFLICT (source, name) DO UPDATE SET last = excluded.last, count = count + 1`, source, name, dom, now, now); err != nil {
		return 0, fmt.Errorf("write the ledger: %w", err)
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM refused_names WHERE source = ? AND name NOT IN
		(SELECT name FROM refused_names WHERE source = ? ORDER BY last DESC, name LIMIT ?)`, source, source, l.refusedMax)
	if err != nil {
		return 0, fmt.Errorf("write the ledger: %w", err)
	}
	n, _ := res.RowsAffected()
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("write the ledger: %w", err)
	}
	return int(n), nil
}

// RefusedFilter narrows RefusedNames. Zero fields do not narrow.
type RefusedFilter struct {
	Source string
	// Since leaves out the names last refused before it.
	Since time.Time
	// Limit is how many at most; 0 means 100.
	Limit int
}

// RefusedNames lists the refused names remembered, the last refused first.
func (l *Ledger) RefusedNames(ctx context.Context, f RefusedFilter) ([]RefusedName, error) {
	stmt := `SELECT source, name, domain, first, last, count FROM refused_names WHERE 1 = 1`
	var args []any
	if f.Source != "" {
		stmt += ` AND source = ?`
		args = append(args, f.Source)
	}
	if !f.Since.IsZero() {
		stmt += ` AND last >= ?`
		args = append(args, formatTime(f.Since))
	}
	limit := f.Limit
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	stmt += ` ORDER BY last DESC, source, name LIMIT ?`
	args = append(args, limit)
	rows, err := l.db.QueryContext(ctx, stmt, args...)
	if err != nil {
		return nil, fmt.Errorf("read the ledger: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []RefusedName
	for rows.Next() {
		var (
			r           RefusedName
			first, last string
		)
		if err := rows.Scan(&r.Source, &r.Name, &r.Domain, &first, &last, &r.Count); err != nil {
			return nil, fmt.Errorf("read the ledger: %w", err)
		}
		if r.First, err = time.Parse(timeFormat, first); err != nil {
			return nil, fmt.Errorf("read the ledger: %w", err)
		}
		if r.Last, err = time.Parse(timeFormat, last); err != nil {
			return nil, fmt.Errorf("read the ledger: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// RefusedName reads one refused name of source, or ErrNotFound.
func (l *Ledger) RefusedName(ctx context.Context, source, name string) (*RefusedName, error) {
	return getRefused(ctx, l.db, source, name)
}

func getRefused(ctx context.Context, db execer, source, name string) (*RefusedName, error) {
	r := &RefusedName{Source: source, Name: name}
	var first, last string
	err := db.QueryRowContext(ctx, `SELECT domain, first, last, count FROM refused_names WHERE source = ? AND name = ?`, source, name).
		Scan(&r.Domain, &first, &last, &r.Count)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("read the ledger: %w", err)
	}
	if r.First, err = time.Parse(timeFormat, first); err != nil {
		return nil, fmt.Errorf("read the ledger: %w", err)
	}
	if r.Last, err = time.Parse(timeFormat, last); err != nil {
		return nil, fmt.Errorf("read the ledger: %w", err)
	}
	return r, nil
}

// CountRefused counts the refused names remembered, for every source.
func (l *Ledger) CountRefused(ctx context.Context) (int, error) {
	var n int
	if err := l.db.QueryRowContext(ctx, `SELECT count(*) FROM refused_names`).Scan(&n); err != nil {
		return 0, fmt.Errorf("read the ledger: %w", err)
	}
	return n, nil
}

// RefusedChoices are the choices and options offered for a refused name.
func RefusedChoices(name string, s routes.ApprovalSettings) ([]Choice, *Options) {
	return destinationChoices(s), DestinationOptions([]string{name})
}

// RefusedGrant is the owner granting a name from the list of refused
// names.
type RefusedGrant struct {
	Source, Name string
	// Inside is whether the name is an inside name, for the grant's
	// summary.
	Inside bool
	// Settings are the approval settings in use: the choices offered are
	// made of them.
	Settings routes.ApprovalSettings
	Choice   string
	Options  OptionAnswer
}

// GrantRefused gives a destination grant for a name in the list of refused
// names. The caller has checked that the name may be granted. record is
// called with the grant before it takes effect, as for Answer.
func (l *Ledger) GrantRefused(ctx context.Context, rg RefusedGrant, record func(*Grant) error) (*Grant, error) {
	choices, opts := RefusedChoices(rg.Name, rg.Settings)
	var choice *Choice
	for i := range choices {
		if choices[i].ID == rg.Choice {
			choice = &choices[i]
		}
	}
	if choice == nil {
		return nil, ErrBadChoice
	}
	c, err := choose(opts, &rg.Options)
	if err != nil {
		return nil, err
	}
	tx, err := l.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("write the ledger: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := getRefused(ctx, tx, rg.Source, rg.Name); err != nil {
		return nil, err
	}
	g := newDestinationGrant("", rg.Source, DestinationFacts(rg.Name, rg.Inside, nil), c, *choice, l.now())
	if err := insertGrant(ctx, tx, g); err != nil {
		return nil, err
	}
	if err := forgetCovered(ctx, tx, g); err != nil {
		return nil, err
	}
	if record != nil {
		if err := record(g); err != nil {
			return nil, fmt.Errorf("the grant could not be recorded, so it was not taken: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("write the ledger: %w", err)
	}
	return g, nil
}

// forgetCovered takes the names g covers off its source's list of refused
// names: they are refused no more.
func forgetCovered(ctx context.Context, db execer, g *Grant) error {
	var err error
	if g.Unit == UnitDomain {
		_, err = db.ExecContext(ctx, `DELETE FROM refused_names WHERE source = ? AND (name = ? OR name LIKE ? ESCAPE '\')`,
			g.Source, g.Name, "%."+strings.NewReplacer(`\`, `\\`, "%", `\%`, "_", `\_`).Replace(g.Name))
	} else {
		_, err = db.ExecContext(ctx, `DELETE FROM refused_names WHERE source = ? AND name = ?`, g.Source, g.Name)
	}
	if err != nil {
		return fmt.Errorf("write the ledger: %w", err)
	}
	return nil
}
