package routes

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Rule matches requests by method and path and names the operation they
// are (docs/adr/0004).
type Rule struct {
	Operation string
	// Methods are upper case. Empty means any method.
	Methods []string
	// segments is the path pattern split at "/". Nil means any path.
	segments []segment
	// Target lists the parameters that make the operation's target, in
	// order.
	Target []string
}

type segment struct {
	literal string
	param   string
	rest    bool
}

// Param is one parameter a rule read from the path.
type Param struct {
	Name, Value string
}

// Match is a request matched to an operation by a rule.
type Match struct {
	Operation string
	// Params are every parameter of the path, in the pattern's order.
	Params []Param
	// Target names the parameters that make the target.
	Target []string
}

// Match finds the first rule of d that matches method and path.
func (d Destination) Match(method, path string) (Match, bool) {
	for _, r := range d.Rules {
		if len(r.Methods) > 0 && !slices.Contains(r.Methods, method) {
			continue
		}
		params, ok := r.matchPath(path)
		if !ok {
			continue
		}
		return Match{Operation: r.Operation, Params: params, Target: r.Target}, true
	}
	return Match{}, false
}

// ActionFor is what the table says to do with the operation named op: its
// row in operations, or else the destination's default. A raw operation
// (no name) always takes the default.
func (d Destination) ActionFor(op string) Action {
	if a, ok := d.Operations[op]; ok && op != "" {
		return a
	}
	return d.Default
}

// HasOperation reports whether some rule of d names op.
func (d Destination) HasOperation(op string) bool {
	for _, r := range d.Rules {
		if r.Operation == op {
			return true
		}
	}
	return false
}

// RuleParams gives the parameters, in order, and the target of the first
// rule that names op.
func (d Destination) RuleParams(op string) (params, target []string, ok bool) {
	for _, r := range d.Rules {
		if r.Operation != op {
			continue
		}
		for _, s := range r.segments {
			if s.param != "" {
				params = append(params, s.param)
			}
		}
		return params, r.Target, true
	}
	return nil, nil, false
}

func (r Rule) matchPath(path string) ([]Param, bool) {
	if r.segments == nil {
		return nil, true
	}
	if !strings.HasPrefix(path, "/") {
		return nil, false
	}
	parts := strings.Split(path[1:], "/")
	var params []Param
	for i, s := range r.segments {
		if s.rest {
			rest := strings.Join(parts[i:], "/")
			if i >= len(parts) || rest == "" {
				return nil, false
			}
			return append(params, Param{s.param, rest}), true
		}
		if i >= len(parts) {
			return nil, false
		}
		switch {
		case s.param != "":
			if parts[i] == "" {
				return nil, false
			}
			params = append(params, Param{s.param, parts[i]})
		case parts[i] != s.literal:
			return nil, false
		}
	}
	if len(parts) != len(r.segments) {
		return nil, false
	}
	return params, true
}

var (
	operationName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	paramName     = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

type rawRule struct {
	Operation string   `yaml:"operation"`
	Methods   []string `yaml:"methods"`
	Path      string   `yaml:"path"`
	Target    []string `yaml:"target"`
}

func (rr rawRule) check() (Rule, error) {
	if !operationName.MatchString(rr.Operation) {
		return Rule{}, fmt.Errorf("operation: %q is not an operation name (letters, digits, '.', '_' and '-')", rr.Operation)
	}
	r := Rule{Operation: rr.Operation}
	for _, m := range rr.Methods {
		m = strings.ToUpper(strings.TrimSpace(m))
		if m == "" {
			return Rule{}, errors.New("methods: an empty method")
		}
		r.Methods = append(r.Methods, m)
	}
	var params []string
	if rr.Path != "" {
		if !strings.HasPrefix(rr.Path, "/") {
			return Rule{}, fmt.Errorf("path: %q does not start with /", rr.Path)
		}
		parts := strings.Split(rr.Path[1:], "/")
		r.segments = []segment{}
		for i, p := range parts {
			s, err := parseSegment(p)
			if err != nil {
				return Rule{}, fmt.Errorf("path: %w", err)
			}
			if s.rest && i != len(parts)-1 {
				return Rule{}, fmt.Errorf("path: {%s...} is not the last segment", s.param)
			}
			if s.param != "" {
				if slices.Contains(params, s.param) {
					return Rule{}, fmt.Errorf("path: {%s} is given twice", s.param)
				}
				params = append(params, s.param)
			}
			r.segments = append(r.segments, s)
		}
	}
	if rr.Target == nil {
		r.Target = params
	} else {
		for _, t := range rr.Target {
			if !slices.Contains(params, t) {
				return Rule{}, fmt.Errorf("target: %q is not a parameter of the path", t)
			}
		}
		r.Target = rr.Target
	}
	return r, nil
}

func parseSegment(p string) (segment, error) {
	open, close := strings.Contains(p, "{"), strings.Contains(p, "}")
	if !open && !close {
		return segment{literal: p}, nil
	}
	if !strings.HasPrefix(p, "{") || !strings.HasSuffix(p, "}") {
		return segment{}, fmt.Errorf("%q: a parameter takes the whole segment", p)
	}
	name := p[1 : len(p)-1]
	s := segment{}
	if n, ok := strings.CutSuffix(name, "..."); ok {
		name, s.rest = n, true
	}
	if !paramName.MatchString(name) {
		return segment{}, fmt.Errorf("%q: %q is not a parameter name", p, name)
	}
	s.param = name
	return s, nil
}

func parseAction(a string) (Action, bool) {
	switch Action(a) {
	case Allow, Ask, Deny:
		return Action(a), true
	}
	return "", false
}

// ApprovalSettings shape what the gate offers when it asks the owner
// (docs/adr/0004).
type ApprovalSettings struct {
	// Durations are the lengths a grant beyond one request can be given
	// for, in the order they are offered. 0 is a grant without an end.
	Durations []time.Duration
	// Once is how long a grant for one request waits to be used.
	Once time.Duration
	// Pending is how long an approval waits for an answer.
	Pending time.Duration
}

func defaultApprovals() ApprovalSettings {
	return ApprovalSettings{
		Durations: []time.Duration{time.Hour, 24 * time.Hour, 30 * 24 * time.Hour, 0},
		Once:      10 * time.Minute,
		Pending:   24 * time.Hour,
	}
}

type rawApprovals struct {
	Durations *[]string `yaml:"durations"`
	Once      string    `yaml:"once"`
	Pending   string    `yaml:"pending"`
}

func (ra rawApprovals) apply(a *ApprovalSettings) error {
	if ra.Durations != nil {
		if len(*ra.Durations) == 0 {
			return errors.New("durations: at least one is required")
		}
		a.Durations = nil
		for _, s := range *ra.Durations {
			if s == "forever" {
				a.Durations = append(a.Durations, 0)
				continue
			}
			d, err := parseDuration(s)
			if err != nil {
				return fmt.Errorf("durations: %w", err)
			}
			a.Durations = append(a.Durations, d)
		}
	}
	for _, f := range []struct {
		name, value string
		to          *time.Duration
	}{{"once", ra.Once, &a.Once}, {"pending", ra.Pending, &a.Pending}} {
		if f.value == "" {
			continue
		}
		d, err := parseDuration(f.value)
		if err != nil {
			return fmt.Errorf("%s: %w", f.name, err)
		}
		*f.to = d
	}
	return nil
}

// parseDuration reads a positive length as Go writes durations, or as a
// whole number of days ("30d").
func parseDuration(s string) (time.Duration, error) {
	var (
		d   time.Duration
		err error
	)
	if n, ok := strings.CutSuffix(s, "d"); ok {
		var days int
		days, err = strconv.Atoi(n)
		d = time.Duration(days) * 24 * time.Hour
	} else {
		d, err = time.ParseDuration(s)
	}
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("%q is not a positive length (such as 30m, 1h or 30d)", s)
	}
	return d, nil
}

// FormatDuration writes d the way the table is written: in days when it is
// a whole number of them, and "forever" for 0.
func FormatDuration(d time.Duration) string {
	switch {
	case d == 0:
		return "forever"
	case d%(24*time.Hour) == 0:
		return fmt.Sprintf("%dd", d/(24*time.Hour))
	case d%time.Hour == 0:
		return fmt.Sprintf("%dh", d/time.Hour)
	case d%time.Minute == 0:
		return fmt.Sprintf("%dm", d/time.Minute)
	}
	return d.String()
}
