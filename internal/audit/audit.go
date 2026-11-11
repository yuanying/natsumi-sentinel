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
	// KindConnection is a connection refused before any request was read:
	// a destination not opened, TLS without a name, plain HTTP, or
	// something that is neither.
	KindConnection Kind = "connection"
	// KindPassthrough is a connection let straight through.
	KindPassthrough Kind = "passthrough"
	// KindDNS is one name resolution query.
	KindDNS Kind = "dns"
	// KindConfig is the gate reading its routing table again.
	KindConfig Kind = "config"
	// KindGate is a request the gate itself sent upstream (a notice).
	KindGate Kind = "gate"
)

// Verdict is how the gate decided.
type Verdict string

const (
	Allow Verdict = "allow"
	Deny  Verdict = "deny"
)

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

	Verdict Verdict `json:"verdict,omitempty"`
	Reason  string  `json:"reason,omitempty"`

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

const schemaVersion = 1

const schema = `
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
	return &Log{db: db, out: out}, nil
}

func migrate(db *sql.DB) error {
	var v int
	if err := db.QueryRow("PRAGMA user_version").Scan(&v); err != nil {
		return fmt.Errorf("read the audit log's version: %w", err)
	}
	switch v {
	case schemaVersion:
		return nil
	case 0:
		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("create the audit log: %w", err)
		}
		defer func() { _ = tx.Rollback() }()
		if _, err := tx.Exec(schema); err != nil {
			return fmt.Errorf("create the audit log: %w", err)
		}
		if _, err := tx.Exec(fmt.Sprintf("PRAGMA user_version = %d", schemaVersion)); err != nil {
			return fmt.Errorf("create the audit log: %w", err)
		}
		return tx.Commit()
	default:
		return fmt.Errorf("the audit log is version %d; this build knows %d", v, schemaVersion)
	}
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
		error = ?, finished = 1
		WHERE id = ?`,
		string(rec.Verdict), rec.Reason,
		text, size, hash, trunc, bin,
		rec.Status, rec.ResponseBytes, rec.BytesUp, rec.BytesDown, int64(rec.Duration),
		rec.Error, rec.ID)
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
		dns_type, dns_rcode, dns_answer, error, finished
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		formatTime(rec.Time), rec.Source, string(rec.Kind), rec.Treatment, rec.Name, rec.Address,
		rec.Method, rec.Path, rec.Query, string(rec.Verdict), rec.Reason,
		text, size, hash, trunc, bin,
		rec.Status, rec.ResponseBytes, rec.BytesUp, rec.BytesDown, int64(rec.Duration),
		rec.DNSType, rec.DNSRcode, string(answer), rec.Error, rec.Finished)
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
	var (
		rec                      Record
		t, kind, verdict, answer string
		text, hash               sql.NullString
		size, trunc, bin         sql.NullInt64
		duration                 int64
	)
	err := l.db.QueryRowContext(ctx, `SELECT
		id, time, source, kind, treatment, name, address, method, path, query, verdict, reason,
		request_text, request_size, request_sha256, request_truncated, request_binary,
		status, response_bytes, bytes_up, bytes_down, duration_ns,
		dns_type, dns_rcode, dns_answer, error, finished
		FROM records WHERE id = ?`, id).Scan(
		&rec.ID, &t, &rec.Source, &kind, &rec.Treatment, &rec.Name, &rec.Address,
		&rec.Method, &rec.Path, &rec.Query, &verdict, &rec.Reason,
		&text, &size, &hash, &trunc, &bin,
		&rec.Status, &rec.ResponseBytes, &rec.BytesUp, &rec.BytesDown, &duration,
		&rec.DNSType, &rec.DNSRcode, &answer, &rec.Error, &rec.Finished)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("read audit record %d: %w", id, err)
	}
	if rec.Time, err = time.Parse(timeFormat, t); err != nil {
		return nil, fmt.Errorf("read audit record %d: %w", id, err)
	}
	rec.Kind = Kind(kind)
	rec.Verdict = Verdict(verdict)
	rec.Duration = time.Duration(duration)
	if size.Valid {
		rec.Request = &Body{Text: text.String, Size: size.Int64, SHA256: hash.String, Truncated: trunc.Int64 != 0, Binary: bin.Int64 != 0}
	}
	if err := json.Unmarshal([]byte(answer), &rec.DNSAnswer); err != nil {
		return nil, fmt.Errorf("read audit record %d: %w", id, err)
	}
	return &rec, nil
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
