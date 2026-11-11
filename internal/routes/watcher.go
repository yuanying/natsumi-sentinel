package routes

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"sync"
	"sync/atomic"
	"time"
)

// Watcher holds the table in use and reads the directory again when its
// contents change. A table that cannot be read is not taken: the one read
// before stays in use (docs/adr/0004).
type Watcher struct {
	dir     string
	current atomic.Pointer[Table]

	mu sync.Mutex
	// seen is the fingerprint of the directory as last checked, whether or
	// not that check gave a table. A broken table is reported once, not on
	// every check.
	seen [sha256.Size]byte
}

// NewWatcher reads dir once. It fails if the table cannot be read, so the
// gate does not start without one (docs/adr/0001).
func NewWatcher(dir string) (*Watcher, error) {
	files, err := readDir(dir)
	if err != nil {
		return nil, err
	}
	t, err := parse(files)
	if err != nil {
		return nil, err
	}
	w := &Watcher{dir: dir, seen: fingerprint(files)}
	w.current.Store(t)
	return w, nil
}

// Current returns the table in use.
func (w *Watcher) Current() *Table { return w.current.Load() }

// Check reads the directory. It reports changed when a new table was taken,
// and an error when the directory changed into something that cannot be
// used. A directory that cannot be read at all is reported every time.
func (w *Watcher) Check() (changed bool, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	files, err := readDir(w.dir)
	if err != nil {
		w.seen = [sha256.Size]byte{}
		return false, err
	}
	fp := fingerprint(files)
	if fp == w.seen {
		return false, nil
	}
	w.seen = fp
	t, err := parse(files)
	if err != nil {
		return false, err
	}
	w.current.Store(t)
	return true, nil
}

// Run checks every interval until ctx is done, and calls report with the
// result of each check that took a table or failed.
func (w *Watcher) Run(ctx context.Context, interval time.Duration, report func(error)) {
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			changed, err := w.Check()
			if changed || err != nil {
				report(err)
			}
		}
	}
}

func fingerprint(files []source) [sha256.Size]byte {
	h := sha256.New()
	for _, f := range files {
		// Lengths first, so that moving bytes between a name and a body
		// cannot give the same fingerprint.
		h.Write(binary.LittleEndian.AppendUint64(nil, uint64(len(f.name))))
		h.Write(binary.LittleEndian.AppendUint64(nil, uint64(len(f.body))))
		h.Write([]byte(f.name))
		h.Write(f.body)
	}
	var out [sha256.Size]byte
	copy(out[:], h.Sum(nil))
	return out
}
