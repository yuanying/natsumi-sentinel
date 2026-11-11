package github

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/yuanying/natsumi-sentinel/internal/audit"
	"github.com/yuanying/natsumi-sentinel/internal/decide"
)

// maxAnswer bounds what the gate reads of an answer to its question.
const maxAnswer = 1 << 20

// errNotFound is a 404: the upstream does not know what was asked about.
var errNotFound = errors.New("not found upstream")

// question is one request the gate sends upstream about a request.
type question struct {
	method, path, query string
	body                []byte
	// why says, in the record, what the question is for.
	why string
}

// ask sends q to the destination's API with the surrogate of req, and
// returns the answer's body. Nothing is asked that could not be recorded
// first. A 404 is errNotFound; any other answer but a 200 is an error.
func (c *Connector) ask(ctx context.Context, req decide.Request, q question, read func(io.Reader) error) error {
	api := req.Destination.GitHub.API
	rec := &audit.Record{
		Time:    c.now(),
		Source:  req.Source,
		Kind:    audit.KindGate,
		Name:    api,
		Method:  q.method,
		Path:    q.path,
		Query:   q.query,
		Verdict: audit.Allow,
		Reason:  "the gate's own question, " + q.why,
	}
	if len(q.body) > 0 {
		rec.Request = &audit.Body{Text: string(q.body), Size: int64(len(q.body))}
	}
	if err := c.Log.Begin(ctx, rec); err != nil {
		return fmt.Errorf("the gate's question could not be recorded, so it was not asked: %w", err)
	}
	start := c.now()
	defer func() {
		rec.Duration = c.now().Sub(start)
		_ = c.Log.Finish(context.WithoutCancel(ctx), rec)
	}()

	u := &url.URL{Scheme: "https", Host: api + ":443", Path: q.path, RawQuery: q.query}
	var body io.Reader = http.NoBody
	if len(q.body) > 0 {
		body = bytes.NewReader(q.body)
	}
	r, err := http.NewRequestWithContext(ctx, q.method, u.String(), body)
	if err != nil {
		rec.Error = err.Error()
		return err
	}
	// The request's own surrogate: the question has no more rights than
	// the request it is about (docs/adr/0003). authd swaps it.
	if a := req.Header.Get("Authorization"); a != "" {
		r.Header.Set("Authorization", a)
	}
	r.Header.Set("Accept", "application/vnd.github+json")
	r.Header.Set("User-Agent", "natsumi-sentinel")
	if len(q.body) > 0 {
		r.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.Transport.RoundTrip(r)
	if err != nil {
		rec.Error = err.Error()
		return fmt.Errorf("the gate's question to %s was not answered: %w", api, err)
	}
	defer func() { _ = resp.Body.Close() }()
	rec.Status = resp.StatusCode
	counted := &counter{r: io.LimitReader(resp.Body, maxAnswer)}
	defer func() { rec.ResponseBytes = counted.n }()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return errNotFound
	case resp.StatusCode != http.StatusOK:
		rec.Error = fmt.Sprintf("%s answered %d", api, resp.StatusCode)
		return fmt.Errorf("the gate's question to %s: %s", api, rec.Error)
	}
	if err := read(counted); err != nil {
		rec.Error = "the answer could not be read: " + err.Error()
		return fmt.Errorf("the gate's question to %s: %s", api, rec.Error)
	}
	return nil
}

type counter struct {
	r io.Reader
	n int64
}

func (c *counter) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// decodeJSON reads one JSON value into v.
func decodeJSON(v any) func(io.Reader) error {
	return func(r io.Reader) error { return json.NewDecoder(r).Decode(v) }
}

// topField reads the top-level field name of a JSON object as a string,
// stopping there: the rest of a long answer is not read.
func topField(name string, into *string) func(io.Reader) error {
	return func(r io.Reader) error {
		dec := json.NewDecoder(r)
		if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
			return errors.New("not a JSON object")
		}
		for dec.More() {
			tok, err := dec.Token()
			if err != nil {
				return err
			}
			if tok == name {
				return dec.Decode(into)
			}
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				return err
			}
		}
		return fmt.Errorf("no %q in the answer", name)
	}
}

// repoPath is /repos/{owner}/{repo} and the rest, each part escaped.
func repoPath(owner, repo string, rest ...string) string {
	parts := []string{"", "repos", url.PathEscape(owner), url.PathEscape(repo)}
	for _, r := range rest {
		parts = append(parts, url.PathEscape(r))
	}
	return strings.Join(parts, "/")
}

// compare asks how head stands to base: GitHub's status of base...head
// (ahead, behind, identical, diverged). ok is false when upstream does
// not know one of them.
func (c *Connector) compare(ctx context.Context, req decide.Request, owner, repo, base, head, why string) (status string, ok bool, err error) {
	// The names of branches can hold "/": each part is escaped, and the
	// slashes stay.
	esc := func(s string) string {
		parts := strings.Split(s, "/")
		for i, p := range parts {
			parts[i] = url.PathEscape(p)
		}
		return strings.Join(parts, "/")
	}
	path := repoPath(owner, repo) + "/compare/" + esc(base) + "..." + esc(head)
	err = c.ask(ctx, req, question{method: http.MethodGet, path: path, query: "per_page=1", why: why}, topField("status", &status))
	if errors.Is(err, errNotFound) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return status, true, nil
}
