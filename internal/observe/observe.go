// Package observe takes what the gate does as it is recorded, and turns it
// into the gate's metrics (docs/metrics.md) and into what the notices are
// made from (internal/notice).
//
// It sits beside the gate rather than in it: Recorder wraps the audit log
// the gate writes to, and tells each record, once written, to whoever
// watches. The gate itself does not know it is watched.
package observe

import (
	"context"

	"github.com/yuanying/natsumi-sentinel/internal/audit"
)

// Log is the audit log as the gate and its name resolution write to it.
type Log interface {
	Write(ctx context.Context, rec *audit.Record) error
	Begin(ctx context.Context, rec *audit.Record) error
	Finish(ctx context.Context, rec *audit.Record) error
}

// Stage is which of the log's calls an event comes from.
type Stage string

const (
	// Write keeps a record that was complete when made.
	Write Stage = "write"
	// Begin keeps a record before what it records is let through.
	Begin Stage = "begin"
	// Finish completes a record begun with Begin.
	Finish Stage = "finish"
)

// Event is one call to the audit log: the record as it was written, and
// the error the log gave, if any.
type Event struct {
	Stage  Stage
	Record audit.Record
	Err    error
}

// Recorder is a Log that tells each call to the log it wraps.
type Recorder struct {
	inner Log
	tell  []func(Event)
}

// NewRecorder returns a Recorder that writes to inner and then tells each
// of tell. tell is called on the goroutine that wrote, so it must be
// quick and must not block.
func NewRecorder(inner Log, tell ...func(Event)) *Recorder {
	return &Recorder{inner: inner, tell: tell}
}

// Write implements Log.
func (r *Recorder) Write(ctx context.Context, rec *audit.Record) error {
	err := r.inner.Write(ctx, rec)
	r.told(Write, rec, err)
	return err
}

// Begin implements Log.
func (r *Recorder) Begin(ctx context.Context, rec *audit.Record) error {
	err := r.inner.Begin(ctx, rec)
	r.told(Begin, rec, err)
	return err
}

// Finish implements Log.
func (r *Recorder) Finish(ctx context.Context, rec *audit.Record) error {
	err := r.inner.Finish(ctx, rec)
	r.told(Finish, rec, err)
	return err
}

func (r *Recorder) told(stage Stage, rec *audit.Record, err error) {
	// A copy, so that what is told does not change under whoever keeps
	// it while the gate goes on with its record.
	ev := Event{Stage: stage, Record: *rec, Err: err}
	if rec.Request != nil {
		body := *rec.Request
		ev.Record.Request = &body
	}
	ev.Record.DNSAnswer = append([]string(nil), rec.DNSAnswer...)
	ev.Record.UpstreamAddress = append([]string(nil), rec.UpstreamAddress...)
	for _, t := range r.tell {
		t(ev)
	}
}
