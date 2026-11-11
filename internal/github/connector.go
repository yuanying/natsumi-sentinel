// Package github is the gate's GitHub connector (docs/adr/0005,
// docs/github.md). It reads the requests to a destination with a GitHub
// section in the routing table, and names them as operations: REST writes
// by the rules, GraphQL mutations by their one field, and git pushes by
// each ref they change. Reads (REST GET and HEAD, GraphQL queries, git
// fetches) go through as reads.
//
// What a request is on is looked up upstream where the request does not
// say it plainly (a node ID, whether a push rewinds a branch, the commit a
// tag is on). The gate asks with the surrogate of the request it is asking
// about, through authd, and records each question as one of its own
// (docs/adr/0003, docs/adr/0006). The connector holds no key.
package github

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/yuanying/natsumi-sentinel/internal/audit"
	"github.com/yuanying/natsumi-sentinel/internal/decide"
)

// Recorder is the audit log as the connector records its own questions.
type Recorder interface {
	Begin(ctx context.Context, rec *audit.Record) error
	Finish(ctx context.Context, rec *audit.Record) error
}

// Connector implements decide.Connector for GitHub.
type Connector struct {
	// Transport sends the gate's questions. In the gate it is the sender
	// to authd, the same one the workspace's requests go through.
	Transport http.RoundTripper
	// Log records each question asked.
	Log    Recorder
	Now    func() time.Time
	Logger *slog.Logger
}

var _ decide.Connector = (*Connector)(nil)

// Read implements decide.Connector.
func (c *Connector) Read(ctx context.Context, req decide.Request) (decide.Result, error) {
	if req.Method == http.MethodGet || req.Method == http.MethodHead {
		return decide.Result{Read: true}, nil
	}
	switch {
	case req.Method == http.MethodPost && strings.HasSuffix(req.Path, "/git-upload-pack"):
		// A fetch or a clone: what the client has and wants, not a write.
		return decide.Result{Read: true}, nil
	case req.Method == http.MethodPost && strings.HasSuffix(req.Path, "/git-receive-pack"):
		return c.push(ctx, req)
	case req.Method == http.MethodPost && req.Path == "/graphql":
		return c.graphql(ctx, req)
	}
	return c.rest(ctx, req)
}

func (c *Connector) now() time.Time {
	if c.Now == nil {
		return time.Now()
	}
	return c.Now()
}

func refuse(format string) decide.Result {
	return decide.Result{Refusal: format}
}
