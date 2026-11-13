// Package audit keeps the gate's records of what went through it
// (docs/adr/0006). The SQLite file is the record that counts; each record is
// also written as one line of JSON to stdout, as a copy for whatever collects
// the container's logs.
//
// A request that cannot be recorded must not go through, so callers write
// the record before they let anything out and treat an error from Write or
// Begin as a refusal.
package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	// The driver is pure Go, so the binary stays static (no cgo) and runs
	// on a distroless base.
	_ "modernc.org/sqlite"
)

// Kind is what a record is about.
type Kind string

const (
	// KindHTTP is one request read on an open destination.
	KindHTTP Kind = "http"
	// KindConnection is a connection that ended before any request was
	// read: one refused (a destination not opened, TLS without a name,
	// plain HTTP, or something that is neither), or one to an open
	// destination nothing was sent on (ReasonConnectionUnused).
	KindConnection Kind = "connection"
	// KindPassthrough is a connection let straight through.
	KindPassthrough Kind = "passthrough"
	// KindDNS is one name resolution query.
	KindDNS Kind = "dns"
	// KindConfig is the gate reading its routing table again.
	KindConfig Kind = "config"
	// KindAgent is the workspace asking the gate for an approval
	// beforehand, through the gate's own address.
	KindAgent Kind = "agent"
	// KindAnswer is the owner's answer to an approval, or the owner
	// revoking a grant, taken on the approvals socket.
	KindAnswer Kind = "answer"
	// KindGate is a request the gate itself sent upstream (a notice).
	KindGate Kind = "gate"
)

// Verdict is how the gate decided.
type Verdict string

const (
	Allow Verdict = "allow"
	// Ask is a request held for the owner's answer (docs/adr/0004).
	Ask  Verdict = "ask"
	Deny Verdict = "deny"
)

// The reasons a name resolution query was refused (docs/audit.md). Each
// starts with what the gate said for all of them before they were told
// apart, so that what looks for that still finds it.
const (
	// ReasonDNSDenied is a name the routing table lists as deny.
	ReasonDNSDenied = "not an open destination in the routing table: the table denies the name"
	// ReasonDNSNotListed is a name the routing table does not list.
	ReasonDNSNotListed = "not an open destination in the routing table: the name is not in the table"
	// ReasonDNSSearchSuffix is a name the routing table lists, with one of
	// the cluster's search suffixes added: the workspace's resolver trying
	// the search list before the name itself. It is not a notice's pair
	// (docs/notices.md).
	ReasonDNSSearchSuffix = "not an open destination in the routing table: a name in the table with a search suffix added"
)

// ReasonConnectionUnused is a TLS connection to an open destination that
// closed before anything was sent on it: a tool that opened a connection
// ahead of a request it then sent on another, or did not send at all. It
// was not refused, so its verdict is allow (docs/audit.md).
const ReasonConnectionUnused = "the connection was closed before anything was sent on it"

// Body is what is kept of a request body: the text up to the limit, and the
// size and hash of the whole. A body that is not text keeps only the size
// and hash.
type Body struct {
	Text      string `json:"text,omitempty"`
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
	Binary    bool   `json:"binary,omitempty"`
}

// Record is one thing that went through the gate, or was refused by it.
// Fields that do not apply to a kind are left empty.
type Record struct {
	ID     int64     `json:"id"`
	Time   time.Time `json:"time"`
	Source string    `json:"source,omitempty"`
	Kind   Kind      `json:"kind"`

	// Treatment is the destination's treatment in the routing table
	// (open, passthrough, deny).
	Treatment string `json:"treatment,omitempty"`
	// Name is the destination's name (SNI and Host, or the queried name).
	Name string `json:"name,omitempty"`
	// Address is the original destination, ip:port.
	Address string `json:"address,omitempty"`

	Method string `json:"method,omitempty"`
	Path   string `json:"path,omitempty"`
	Query  string `json:"query,omitempty"`
	// Read is a request that only reads: by its method (GET, HEAD,
	// OPTIONS, TRACE), or as a connector read it whatever its method (a
	// git fetch, a GraphQL query). It is false for a write and for the
	// kinds that are not requests.
	Read bool `json:"read,omitempty"`

	Verdict Verdict `json:"verdict,omitempty"`
	Reason  string  `json:"reason,omitempty"`

	// Operation is the name of the operation the request was matched to,
	// and Target its target, as "key=value" pairs in the order the rule
	// gives (docs/adr/0004). Both are empty for a raw operation.
	Operation string `json:"operation,omitempty"`
	Target    string `json:"target,omitempty"`
	// Approval is the approval the record is about: the one a request was
	// held for, or the one the owner answered.
	Approval string `json:"approval,omitempty"`
	// Grant is the grant the request went through on, or the one revoked.
	Grant string `json:"grant,omitempty"`

	Request       *Body         `json:"request,omitempty"`
	Status        int           `json:"status,omitempty"`
	ResponseBytes int64         `json:"responseBytes,omitempty"`
	BytesUp       int64         `json:"bytesUp,omitempty"`
	BytesDown     int64         `json:"bytesDown,omitempty"`
	Duration      time.Duration `json:"durationNs,omitempty"`

	DNSType   string   `json:"dnsType,omitempty"`
	DNSRcode  string   `json:"dnsRcode,omitempty"`
	DNSAnswer []string `json:"dnsAnswer,omitempty"`

	Error string `json:"error,omitempty"`
	// AuthdReason is the reason authd gave for not handing back an
	// upstream's response (docs/authd-protocol.md).
	AuthdReason string `json:"authdReason,omitempty"`
	// UpstreamAddress is where the gate connected when it sent upstream
	// itself (ip:port), or, when it refused to connect by the addresses
	// the name was looked up to, each of those (docs/destination-grants.md
	// "記録に足すもの"). Empty for what authd sends.
	UpstreamAddress []string `json:"upstreamAddress,omitempty"`

	// Finished is false between Begin and Finish: a record that stays
	// unfinished was cut off (the gate stopped while it was in flight).
	Finished bool `json:"finished"`
}

// Log is the gate's audit log.
type Log struct {
	db *sql.DB

	mu  sync.Mutex
	out io.Writer
}

const schemaVersion = 4

// schemaV1 is the table as its first version had it. Each later version
// adds to it with the statements in upgrades.
const schemaV1 = `
CREATE TABLE records (
	id INTEGER PRIMARY KEY,
	time TEXT NOT NULL,
	source TEXT NOT NULL,
	kind TEXT NOT NULL,
	treatment TEXT NOT NULL,
	name TEXT NOT NULL,
	address TEXT NOT NULL,
	method TEXT NOT NULL,
	path TEXT NOT NULL,
	query TEXT NOT NULL,
	verdict TEXT NOT NULL,
	reason TEXT NOT NULL,
	request_text TEXT,
	request_size INTEGER,
	request_sha256 TEXT,
	request_truncated INTEGER,
	request_binary INTEGER,
	status INTEGER NOT NULL,
	response_bytes INTEGER NOT NULL,
	bytes_up INTEGER NOT NULL,
	bytes_down INTEGER NOT NULL,
	duration_ns INTEGER NOT NULL,
	dns_type TEXT NOT NULL,
	dns_rcode TEXT NOT NULL,
	dns_answer TEXT NOT NULL,
	error TEXT NOT NULL,
	finished INTEGER NOT NULL
);
CREATE INDEX records_time ON records (time);
`

// upgrades[i] takes the table from version i+1 to i+2.
var upgrades = []string{
	`ALTER TABLE records ADD COLUMN operation TEXT NOT NULL DEFAULT '';
	ALTER TABLE records ADD COLUMN target TEXT NOT NULL DEFAULT '';
	ALTER TABLE records ADD COLUMN approval TEXT NOT NULL DEFAULT '';
	ALTER TABLE records ADD COLUMN grant_id TEXT NOT NULL DEFAULT '';
	ALTER TABLE records ADD COLUMN authd_reason TEXT NOT NULL DEFAULT '';
	CREATE INDEX records_source_verdict ON records (source, verdict, id);`,
	// The requests recorded before are reads by their method alone.
	`ALTER TABLE records ADD COLUMN read INTEGER NOT NULL DEFAULT 0;
	UPDATE records SET read = 1 WHERE kind = 'http' AND method IN ('GET', 'HEAD', 'OPTIONS', 'TRACE');`,
	// Where the gate itself connected; nothing before it did.
	`ALTER TABLE records ADD COLUMN upstream_address TEXT NOT NULL DEFAULT '';`,
}

// Open opens the SQLite file at path, creating it if it does not exist, and
// copies each finished record to out. The directory must exist: a missing
// volume is a mistake to stop on, not something to create.
func Open(path string, out io.Writer) (*Log, error) {
	if _, err := os.Stat(filepath.Dir(path)); err != nil {
		return nil, fmt.Errorf("the audit log's directory: %w", err)
	}
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)")
	if err != nil {
		return nil, fmt.Errorf("open the audit log: %w", err)
	}
	// One writer at a time is what SQLite allows anyway; holding one
	// connection keeps the pragmas on it.
	db.SetMaxOpenConns(1)
	if err := migrate(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := createSeen(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Log{db: db, out: out}, nil
}

func migrate(db *sql.DB) error {
	var v int
	if err := db.QueryRow("PRAGMA user_version").Scan(&v); err != nil {
		return fmt.Errorf("read the audit log's version: %w", err)
	}
	if v == schemaVersion {
		return nil
	}
	if v > schemaVersion {
		return fmt.Errorf("the audit log is version %d; this build knows %d", v, schemaVersion)
	}
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("move the audit log to version %d: %w", schemaVersion, err)
	}
	defer func() { _ = tx.Rollback() }()
	if v == 0 {
		if _, err := tx.Exec(schemaV1); err != nil {
			return fmt.Errorf("create the audit log: %w", err)
		}
		v = 1
	}
	for ; v < schemaVersion; v++ {
		if _, err := tx.Exec(upgrades[v-1]); err != nil {
			return fmt.Errorf("move the audit log to version %d: %w", v+1, err)
		}
	}
	if _, err := tx.Exec(fmt.Sprintf("PRAGMA user_version = %d", schemaVersion)); err != nil {
		return fmt.Errorf("move the audit log to version %d: %w", schemaVersion, err)
	}
	return tx.Commit()
}

// Close closes the SQLite file.
func (l *Log) Close() error { return l.db.Close() }

// Write keeps a record that is complete when it is made (a name resolution
// query, a refusal). It sets rec.ID.
func (l *Log) Write(ctx context.Context, rec *Record) error {
	rec.Finished = true
	if err := l.insert(ctx, rec); err != nil {
		return err
	}
	l.copyOut(rec)
	return nil
}

// Begin keeps a record before what it records is let through, so that
// nothing goes out unrecorded. It sets rec.ID. Finish fills in the rest.
func (l *Log) Begin(ctx context.Context, rec *Record) error {
	rec.Finished = false
	return l.insert(ctx, rec)
}

// Finish writes what is known once a record begun with Begin is over, and
// copies the record to stdout.
func (l *Log) Finish(ctx context.Context, rec *Record) error {
	rec.Finished = true
	text, size, hash, trunc, bin := bodyColumns(rec.Request)
	_, err := l.db.ExecContext(ctx, `UPDATE records SET
		verdict = ?, reason = ?,
		request_text = ?, request_size = ?, request_sha256 = ?, request_truncated = ?, request_binary = ?,
		status = ?, response_bytes = ?, bytes_up = ?, bytes_down = ?, duration_ns = ?,
		error = ?, authd_reason = ?, grant_id = ?, upstream_address = ?, finished = 1
		WHERE id = ?`,
		string(rec.Verdict), rec.Reason,
		text, size, hash, trunc, bin,
		rec.Status, rec.ResponseBytes, rec.BytesUp, rec.BytesDown, int64(rec.Duration),
		rec.Error, rec.AuthdReason, rec.Grant, addressColumn(rec.UpstreamAddress), rec.ID)
	if err != nil {
		return fmt.Errorf("finish audit record %d: %w", rec.ID, err)
	}
	l.copyOut(rec)
	return nil
}

func (l *Log) insert(ctx context.Context, rec *Record) error {
	answer, err := json.Marshal(nonNil(rec.DNSAnswer))
	if err != nil {
		return err
	}
	text, size, hash, trunc, bin := bodyColumns(rec.Request)
	res, err := l.db.ExecContext(ctx, `INSERT INTO records (
		time, source, kind, treatment, name, address, method, path, query, verdict, reason,
		request_text, request_size, request_sha256, request_truncated, request_binary,
		status, response_bytes, bytes_up, bytes_down, duration_ns,
		dns_type, dns_rcode, dns_answer, error, finished,
		operation, target, approval, grant_id, authd_reason, read, upstream_address
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		formatTime(rec.Time), rec.Source, string(rec.Kind), rec.Treatment, rec.Name, rec.Address,
		rec.Method, rec.Path, rec.Query, string(rec.Verdict), rec.Reason,
		text, size, hash, trunc, bin,
		rec.Status, rec.ResponseBytes, rec.BytesUp, rec.BytesDown, int64(rec.Duration),
		rec.DNSType, rec.DNSRcode, string(answer), rec.Error, rec.Finished,
		rec.Operation, rec.Target, rec.Approval, rec.Grant, rec.AuthdReason, rec.Read, addressColumn(rec.UpstreamAddress))
	if err != nil {
		return fmt.Errorf("write audit record: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return fmt.Errorf("write audit record: %w", err)
	}
	rec.ID = id
	return nil
}

// copyOut writes the record to stdout. The copy is not the record that
// counts, so a failure here does not undo the record.
func (l *Log) copyOut(rec *Record) {
	line, err := json.Marshal(rec)
	if err != nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = l.out.Write(append(line, '\n'))
}

// ErrNotFound is returned by Get for an id that is not in the log.
var ErrNotFound = errors.New("no such audit record")

// Get reads one record back.
func (l *Log) Get(ctx context.Context, id int64) (*Record, error) {
	rec, err := scanRecord(l.db.QueryRowContext(ctx, `SELECT `+columns+` FROM records WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("read audit record %d: %w", id, err)
	}
	return rec, nil
}

const columns = `id, time, source, kind, treatment, name, address, method, path, query, verdict, reason,
	request_text, request_size, request_sha256, request_truncated, request_binary,
	status, response_bytes, bytes_up, bytes_down, duration_ns,
	dns_type, dns_rcode, dns_answer, error, finished,
	operation, target, approval, grant_id, authd_reason, read, upstream_address`

type scanner interface{ Scan(dest ...any) error }

func scanRecord(row scanner) (*Record, error) {
	var (
		rec                      Record
		t, kind, verdict, answer string
		upstreamAddr             string
		text, hash               sql.NullString
		size, trunc, bin         sql.NullInt64
		duration                 int64
	)
	err := row.Scan(
		&rec.ID, &t, &rec.Source, &kind, &rec.Treatment, &rec.Name, &rec.Address,
		&rec.Method, &rec.Path, &rec.Query, &verdict, &rec.Reason,
		&text, &size, &hash, &trunc, &bin,
		&rec.Status, &rec.ResponseBytes, &rec.BytesUp, &rec.BytesDown, &duration,
		&rec.DNSType, &rec.DNSRcode, &answer, &rec.Error, &rec.Finished,
		&rec.Operation, &rec.Target, &rec.Approval, &rec.Grant, &rec.AuthdReason, &rec.Read, &upstreamAddr)
	if err != nil {
		return nil, err
	}
	if upstreamAddr != "" {
		rec.UpstreamAddress = strings.Split(upstreamAddr, " ")
	}
	if rec.Time, err = time.Parse(timeFormat, t); err != nil {
		return nil, err
	}
	rec.Kind = Kind(kind)
	rec.Verdict = Verdict(verdict)
	rec.Duration = time.Duration(duration)
	if size.Valid {
		rec.Request = &Body{Text: text.String, Size: size.Int64, SHA256: hash.String, Truncated: trunc.Int64 != 0, Binary: bin.Int64 != 0}
	}
	if err := json.Unmarshal([]byte(answer), &rec.DNSAnswer); err != nil {
		return nil, err
	}
	return &rec, nil
}

// Query narrows the records List reads. Zero fields do not narrow.
type Query struct {
	Source   string
	Kind     Kind
	Verdicts []Verdict
	// Since keeps the records made at or after it.
	Since time.Time
	// Before keeps the records with an id below it, for reading on from
	// the last page.
	Before int64
	// Limit is how many records at most; 0 means 100, and more than 1000
	// is 1000.
	Limit int
}

// List reads the records q asks for, newest first.
func (l *Log) List(ctx context.Context, q Query) ([]*Record, error) {
	var (
		where []string
		args  []any
	)
	if q.Source != "" {
		where = append(where, "source = ?")
		args = append(args, q.Source)
	}
	if q.Kind != "" {
		where = append(where, "kind = ?")
		args = append(args, string(q.Kind))
	}
	if len(q.Verdicts) > 0 {
		marks := strings.TrimSuffix(strings.Repeat("?,", len(q.Verdicts)), ",")
		where = append(where, "verdict IN ("+marks+")")
		for _, v := range q.Verdicts {
			args = append(args, string(v))
		}
	}
	if !q.Since.IsZero() {
		where = append(where, "time >= ?")
		args = append(args, formatTime(q.Since))
	}
	if q.Before > 0 {
		where = append(where, "id < ?")
		args = append(args, q.Before)
	}
	limit := q.Limit
	switch {
	case limit <= 0:
		limit = 100
	case limit > 1000:
		limit = 1000
	}
	stmt := `SELECT ` + columns + ` FROM records`
	if len(where) > 0 {
		stmt += " WHERE " + strings.Join(where, " AND ")
	}
	stmt += " ORDER BY id DESC LIMIT ?"
	args = append(args, limit)
	rows, err := l.db.QueryContext(ctx, stmt, args...)
	if err != nil {
		return nil, fmt.Errorf("list audit records: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*Record
	for rows.Next() {
		rec, err := scanRecord(rows)
		if err != nil {
			return nil, fmt.Errorf("list audit records: %w", err)
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list audit records: %w", err)
	}
	return out, nil
}

// Prune deletes the records made before cutoff and reports how many it
// deleted.
func (l *Log) Prune(ctx context.Context, cutoff time.Time) (int64, error) {
	res, err := l.db.ExecContext(ctx, `DELETE FROM records WHERE time < ?`, formatTime(cutoff))
	if err != nil {
		return 0, fmt.Errorf("prune the audit log: %w", err)
	}
	return res.RowsAffected()
}

// timeFormat has a fixed width, so that the text sorts in time order.
const timeFormat = "2006-01-02T15:04:05.000000000Z07:00"

func formatTime(t time.Time) string { return t.UTC().Format(timeFormat) }

func bodyColumns(b *Body) (text, size, hash, trunc, bin any) {
	if b == nil {
		return nil, nil, nil, nil, nil
	}
	return b.Text, b.Size, b.SHA256, b.Truncated, b.Binary
}

// addressColumn keeps addresses separated by spaces, which no address has.
func addressColumn(addrs []string) string { return strings.Join(addrs, " ") }

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// RunPruner deletes the records older than retention() when it starts and
// then every interval (once a day in the gate), until ctx is done. The
// retention is asked for each time, so a table read again changes it.
func RunPruner(ctx context.Context, l *Log, interval time.Duration, retention func() time.Duration, report func(deleted int64, err error)) {
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		n, err := l.Prune(ctx, time.Now().Add(-retention()))
		report(n, err)
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
