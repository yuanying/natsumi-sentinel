package audit

import (
	"context"
	"fmt"
	"time"
)

// WriteCount is how many writes went to one destination with one method.
type WriteCount struct {
	Name   string
	Method string
	Count  int64
}

// RefusalCount is how many requests were refused (or, later, asked about)
// alike: the same verdict, kind, destination, method, path and reason.
type RefusalCount struct {
	Verdict Verdict
	Kind    Kind
	Name    string
	Method  string
	Path    string
	Reason  string
	Count   int64
}

// Day is what the records of a period count up to, for the daily summary
// (docs/notices.md).
type Day struct {
	// Writes are the writes let through on open destinations, most first.
	Writes []WriteCount
	// Refusals are what was not let through, most first. Reading the
	// routing table again and the gate's own requests are not in it.
	Refusals []RefusalCount
}

// Day counts the records made from from up to to.
func (l *Log) Day(ctx context.Context, from, to time.Time) (*Day, error) {
	f, t := formatTime(from), formatTime(to)
	d := &Day{}
	rows, err := l.db.QueryContext(ctx, `SELECT name, method, count(*) AS n FROM records
		WHERE time >= ? AND time < ? AND kind = ? AND verdict = ?
			AND method NOT IN ('GET', 'HEAD', 'OPTIONS', 'TRACE')
		GROUP BY name, method ORDER BY n DESC, name, method`, f, t, string(KindHTTP), string(Allow))
	if err != nil {
		return nil, fmt.Errorf("count the writes: %w", err)
	}
	for rows.Next() {
		var w WriteCount
		if err := rows.Scan(&w.Name, &w.Method, &w.Count); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("count the writes: %w", err)
		}
		d.Writes = append(d.Writes, w)
	}
	_ = rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("count the writes: %w", err)
	}

	rows, err = l.db.QueryContext(ctx, `SELECT verdict, kind, name, method, path, reason, count(*) AS n FROM records
		WHERE time >= ? AND time < ? AND verdict NOT IN (?, '') AND kind NOT IN (?, ?)
		GROUP BY verdict, kind, name, method, path, reason ORDER BY n DESC, verdict, kind, name, method, path, reason`,
		f, t, string(Allow), string(KindConfig), string(KindGate))
	if err != nil {
		return nil, fmt.Errorf("count the refusals: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var (
			r             RefusalCount
			verdict, kind string
		)
		if err := rows.Scan(&verdict, &kind, &r.Name, &r.Method, &r.Path, &r.Reason, &r.Count); err != nil {
			return nil, fmt.Errorf("count the refusals: %w", err)
		}
		r.Verdict, r.Kind = Verdict(verdict), Kind(kind)
		d.Refusals = append(d.Refusals, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("count the refusals: %w", err)
	}
	return d, nil
}
