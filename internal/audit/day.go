package audit

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// WriteCount is how many writes went to one destination as one operation,
// or, for a raw operation, with one method.
type WriteCount struct {
	Name      string
	Operation string
	// Method is empty when Operation is not.
	Method string
	Count  int64
}

// RefusalCount is how many requests were not let through alike: the same
// verdict, kind, destination and reason, and the same operation and
// target, or for a raw operation the same method and path.
type RefusalCount struct {
	Verdict   Verdict
	Kind      Kind
	Name      string
	Operation string
	Target    string
	// Method and Path are empty when Operation is not.
	Method string
	Path   string
	Reason string
	Count  int64
}

// Answer is one answer of the owner's, or one revocation, as recorded.
type Answer struct {
	Time      time.Time
	Source    string
	Verdict   Verdict
	Name      string
	Operation string
	Target    string
	Method    string
	Path      string
	Approval  string
	Grant     string
	Reason    string
}

// Day is what the records of a period count up to, for the daily summary
// (docs/notices.md).
type Day struct {
	// Writes are the writes let through on open destinations, most first.
	Writes []WriteCount
	// Asks are the requests held for the owner and the operations asked
	// for beforehand, most first.
	Asks []RefusalCount
	// Denials are what was denied, most first. Reading the routing table
	// again, the gate's own requests and the owner's answers are not in
	// it.
	Denials []RefusalCount
	// Answers are the owner's answers and revocations, oldest first.
	Answers []Answer
}

// Day counts the records made from from up to to.
func (l *Log) Day(ctx context.Context, from, to time.Time) (*Day, error) {
	f, t := formatTime(from), formatTime(to)
	d := &Day{}
	err := l.each(ctx, "count the writes", func(rows *sql.Rows) error {
		var w WriteCount
		if err := rows.Scan(&w.Name, &w.Operation, &w.Method, &w.Count); err != nil {
			return err
		}
		d.Writes = append(d.Writes, w)
		return nil
	}, `SELECT name, operation, CASE WHEN operation = '' THEN method ELSE '' END AS m, count(*) AS n FROM records
		WHERE time >= ? AND time < ? AND kind = ? AND verdict = ?
			AND method NOT IN ('GET', 'HEAD', 'OPTIONS', 'TRACE') AND read = 0
		GROUP BY name, operation, m ORDER BY n DESC, name, operation, m`, f, t, string(KindHTTP), string(Allow))
	if err != nil {
		return nil, err
	}
	if d.Asks, err = l.refusals(ctx, f, t, Ask); err != nil {
		return nil, err
	}
	if d.Denials, err = l.refusals(ctx, f, t, Deny); err != nil {
		return nil, err
	}
	err = l.each(ctx, "list the answers", func(rows *sql.Rows) error {
		var (
			a           Answer
			at, verdict string
		)
		if err := rows.Scan(&at, &a.Source, &verdict, &a.Name, &a.Operation, &a.Target, &a.Method, &a.Path, &a.Approval, &a.Grant, &a.Reason); err != nil {
			return err
		}
		tm, err := time.Parse(timeFormat, at)
		if err != nil {
			return err
		}
		a.Time, a.Verdict = tm, Verdict(verdict)
		d.Answers = append(d.Answers, a)
		return nil
	}, `SELECT time, source, verdict, name, operation, target, method, path, approval, grant_id, reason FROM records
		WHERE time >= ? AND time < ? AND kind = ? ORDER BY time, id`, f, t, string(KindAnswer))
	if err != nil {
		return nil, err
	}
	return d, nil
}

// refusals counts the records of a verdict that was not to let through.
func (l *Log) refusals(ctx context.Context, from, to string, v Verdict) ([]RefusalCount, error) {
	var out []RefusalCount
	err := l.each(ctx, "count the "+string(v)+"s", func(rows *sql.Rows) error {
		var (
			r    RefusalCount
			kind string
		)
		if err := rows.Scan(&kind, &r.Name, &r.Operation, &r.Target, &r.Method, &r.Path, &r.Reason, &r.Count); err != nil {
			return err
		}
		r.Verdict, r.Kind = v, Kind(kind)
		out = append(out, r)
		return nil
	}, `SELECT kind, name, operation, target,
			CASE WHEN operation = '' THEN method ELSE '' END AS m,
			CASE WHEN operation = '' THEN path ELSE '' END AS p,
			reason, count(*) AS n FROM records
		WHERE time >= ? AND time < ? AND verdict = ? AND kind NOT IN (?, ?, ?)
		GROUP BY kind, name, operation, target, m, p, reason
		ORDER BY n DESC, kind, name, operation, target, m, p, reason`,
		from, to, string(v), string(KindConfig), string(KindGate), string(KindAnswer))
	return out, err
}

// each runs a query and gives each row to scan.
func (l *Log) each(ctx context.Context, what string, scan func(*sql.Rows) error, query string, args ...any) error {
	rows, err := l.db.QueryContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		if err := scan(rows); err != nil {
			return fmt.Errorf("%s: %w", what, err)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	return nil
}
