package audit

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// Seen is one pair the gate has seen go through, and when it first did
// (docs/notices.md). The pairs are kept apart from the records and are not
// pruned with them, so that a pair seen once stays known after its records
// are gone (docs/adr/0006).
type Seen struct {
	// Pair is what kind of pair it is (a destination, a write, ...).
	Pair string
	// Key is the pair itself, in a form set by the kind of pair.
	Key string
	// First is the time of the record it was first seen in.
	First time.Time
	// Record is the id of that record.
	Record int64
}

// The table is made when it is missing, whatever user_version says: it is
// kept apart from the records, and its form does not change with theirs.
const seenSchema = `
CREATE TABLE IF NOT EXISTS seen (
	pair TEXT NOT NULL,
	key TEXT NOT NULL,
	first_time TEXT NOT NULL,
	first_record INTEGER NOT NULL,
	PRIMARY KEY (pair, key)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS seen_first_time ON seen (first_time);
`

func createSeen(db *sql.DB) error {
	if _, err := db.Exec(seenSchema); err != nil {
		return fmt.Errorf("create the table of pairs seen: %w", err)
	}
	return nil
}

// MarkSeen keeps s unless its pair and key are already kept, and reports
// whether they were new.
func (l *Log) MarkSeen(ctx context.Context, s Seen) (bool, error) {
	res, err := l.db.ExecContext(ctx, `INSERT OR IGNORE INTO seen (pair, key, first_time, first_record) VALUES (?, ?, ?, ?)`,
		s.Pair, s.Key, formatTime(s.First), s.Record)
	if err != nil {
		return false, fmt.Errorf("keep a pair seen: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("keep a pair seen: %w", err)
	}
	return n == 1, nil
}

// SeenBetween lists the pairs first seen from from up to to, oldest first.
func (l *Log) SeenBetween(ctx context.Context, from, to time.Time) ([]Seen, error) {
	rows, err := l.db.QueryContext(ctx, `SELECT pair, key, first_time, first_record FROM seen
		WHERE first_time >= ? AND first_time < ? ORDER BY first_time, pair, key`, formatTime(from), formatTime(to))
	if err != nil {
		return nil, fmt.Errorf("list the pairs seen: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Seen
	for rows.Next() {
		var (
			s Seen
			t string
		)
		if err := rows.Scan(&s.Pair, &s.Key, &t, &s.Record); err != nil {
			return nil, fmt.Errorf("list the pairs seen: %w", err)
		}
		if s.First, err = time.Parse(timeFormat, t); err != nil {
			return nil, fmt.Errorf("list the pairs seen: %w", err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list the pairs seen: %w", err)
	}
	return out, nil
}
