package github

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/yuanying/natsumi-sentinel/internal/audit"
	"github.com/yuanying/natsumi-sentinel/internal/decide"
	"github.com/yuanying/natsumi-sentinel/internal/routes"
)

// command is one ref a push changes.
type command struct {
	old, new, ref string
}

func (c command) line() string { return c.old + " " + c.new + " " + c.ref }

func isZero(oid string) bool { return strings.Trim(oid, "0") == "" }

// push reads the commands at the start of a git-receive-pack request, and
// names each ref it changes (docs/adr/0005). The pack after them is not
// read. A request whose commands cannot be read is refused.
func (c *Connector) push(ctx context.Context, req decide.Request) (decide.Result, error) {
	owner, repo, ok := pushRepo(req.Path)
	if !ok {
		return refuse("a push has to be to /{owner}/{repo}/git-receive-pack"), nil
	}
	if ce := req.Header.Get("Content-Encoding"); ce != "" && ce != "identity" {
		return refuse("a push with a Content-Encoding (" + ce + ") cannot have its commands read"), nil
	}
	cmds, err := readCommands(req.Body)
	if err != nil {
		return refuse("the commands of the push could not be read: " + err.Error()), nil
	}
	gh := req.Destination.GitHub
	var (
		ops  []decide.Operation
		kept strings.Builder
	)
	for _, cmd := range cmds {
		kept.WriteString(cmd.line() + "\n")
		kind, facts := "update", []routes.Param(nil)
		switch {
		case isZero(cmd.old):
			kind = "create"
		case isZero(cmd.new):
			kind = "delete"
			facts = append(facts, routes.Param{Name: "old", Value: cmd.old})
		default:
			ff, err := c.fastForward(ctx, req, owner, repo, cmd)
			if err != nil {
				return decide.Result{}, err
			}
			if ff == "no" {
				kind = "force"
			}
			facts = append(facts, routes.Param{Name: "old", Value: cmd.old}, routes.Param{Name: "fastForward", Value: ff})
		}
		facts = append([]routes.Param{{Name: "kind", Value: kind}}, facts...)

		params := []routes.Param{{Name: "owner", Value: owner}, {Name: "repo", Value: repo}, {Name: "ref", Value: cmd.ref}}
		name := ""
		if m, ok := gh.MatchPush(kind, cmd.ref); ok {
			name = m.Operation
			params = append(params, m.Params...)
		}
		if kind != "delete" {
			params = append(params, routes.Param{Name: "sha", Value: cmd.new})
		}
		if kind == "create" && strings.HasPrefix(cmd.ref, "refs/tags/") {
			tf, refusal, err := c.tagFacts(ctx, req, owner, repo, cmd.new)
			if err != nil || refusal != "" {
				return refuse(refusal), err
			}
			facts = append(facts, tf...)
		}
		ops = append(ops, decide.Operation{
			Name:        name,
			Params:      params,
			Target:      []string{"owner", "repo", "ref"},
			Facts:       facts,
			Fingerprint: refFingerprint(req, cmd),
		})
	}
	return decide.Result{Operations: ops, Request: &audit.Body{Text: kept.String()}}, nil
}

// fastForward asks upstream whether cmd's new commit follows its old one:
// "yes", "no", or "unknown" when upstream does not know the new commit
// (it is in the pack being pushed).
func (c *Connector) fastForward(ctx context.Context, req decide.Request, owner, repo string, cmd command) (string, error) {
	status, ok, err := c.compare(ctx, req, owner, repo, cmd.old, cmd.new, "to find whether a push to "+cmd.ref+" rewinds it")
	switch {
	case err != nil:
		return "", err
	case !ok:
		return "unknown", nil
	case status == "ahead" || status == "identical":
		return "yes", nil
	}
	return "no", nil
}

// refFingerprint is what a grant of one request is matched by for one ref
// of a push: the pack after the commands is not the same each time it is
// made.
func refFingerprint(req decide.Request, cmd command) string {
	h := sha256.New()
	for _, s := range []string{"push", req.Source, req.Destination.Name, strconv.Itoa(int(req.Port)), req.Path, cmd.line()} {
		_, _ = fmt.Fprintf(h, "%d:%s", len(s), s)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// pushRepo reads /{owner}/{repo}[.git]/git-receive-pack.
func pushRepo(path string) (owner, repo string, ok bool) {
	parts := strings.Split(path, "/")
	if len(parts) != 4 || parts[0] != "" || parts[3] != "git-receive-pack" {
		return "", "", false
	}
	owner, repo = strings.ToLower(parts[1]), strings.ToLower(strings.TrimSuffix(parts[2], ".git"))
	if owner == "" || repo == "" {
		return "", "", false
	}
	return owner, repo, true
}

// readCommands reads the pkt-lines of a receive-pack request up to the
// first flush: shallow lines, then one command per ref (the first carrying
// the capabilities after a NUL).
func readCommands(b []byte) ([]command, error) {
	var (
		cmds []command
		seen = map[string]bool{}
	)
	for {
		if len(b) < 4 {
			return nil, errors.New("the commands end before their flush")
		}
		n, err := strconv.ParseUint(string(b[:4]), 16, 16)
		if err != nil {
			return nil, errors.New("not pkt-lines")
		}
		if n == 0 {
			break
		}
		if n < 5 || int(n) > len(b) {
			return nil, errors.New("a pkt-line's length is not what follows")
		}
		line := string(b[4:n])
		b = b[n:]
		line = strings.TrimSuffix(line, "\n")
		if len(cmds) == 0 {
			if oid, ok := strings.CutPrefix(line, "shallow "); ok && isOID(oid) {
				continue
			}
			line, _, _ = strings.Cut(line, "\x00")
		}
		fields := strings.Split(line, " ")
		if len(fields) != 3 || !isOID(fields[0]) || !isOID(fields[1]) || len(fields[0]) != len(fields[1]) {
			return nil, errors.New("a line is not a command (old SHA, new SHA, ref)")
		}
		cmd := command{old: fields[0], new: fields[1], ref: fields[2]}
		if !validRef(cmd.ref) {
			return nil, fmt.Errorf("%q is not a ref", cmd.ref)
		}
		if isZero(cmd.old) && isZero(cmd.new) {
			return nil, fmt.Errorf("the command for %s changes nothing", cmd.ref)
		}
		if seen[cmd.ref] {
			return nil, fmt.Errorf("%s is given twice", cmd.ref)
		}
		seen[cmd.ref] = true
		cmds = append(cmds, cmd)
	}
	if len(cmds) == 0 {
		return nil, errors.New("there is no command")
	}
	return cmds, nil
}

// isOID is a SHA-1 or SHA-256 object ID in lower case hex.
func isOID(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// validRef is a full ref name without what git never puts in one.
func validRef(ref string) bool {
	if !strings.HasPrefix(ref, "refs/") || strings.HasSuffix(ref, "/") || strings.Contains(ref, "..") {
		return false
	}
	for _, c := range ref {
		if c <= ' ' || c == 0x7f || strings.ContainsRune("~^:?*[\\", c) {
			return false
		}
	}
	return true
}
