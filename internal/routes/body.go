package routes

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
)

// Body is a request body read as one JSON object, for the rules that look
// at its fields. Only a body read whole is one.
type Body struct {
	fields map[string]string
}

// ParseBody reads b as one JSON object. complete says whether b is the whole
// body. It returns nil when b is not the whole body, not one JSON object, or
// gives a field twice (readers disagree on which one counts), so that no
// rule with body fields matches it.
func ParseBody(b []byte, complete bool) *Body {
	if !complete {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return nil
	}
	fields := map[string]string{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil
		}
		key, ok := tok.(string)
		if !ok {
			return nil
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil
		}
		if _, dup := fields[key]; dup {
			return nil
		}
		fields[key] = scalarText(raw)
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return nil
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil
	}
	return &Body{fields: fields}
}

// Field gives the text of a scalar field: a string as it is, a number or a
// boolean as JSON writes it. ok is false for a field that is missing, null,
// an object or an array.
func (b *Body) Field(name string) (string, bool) {
	if b == nil {
		return "", false
	}
	v, ok := b.fields[name]
	if !ok || v == "\x00" {
		return "", false
	}
	return v, true
}

// scalarText is the text of a scalar, or "\x00" for anything else (no
// JSON scalar's text holds a NUL byte unescaped).
func scalarText(raw json.RawMessage) string {
	var v any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return "\x00"
	}
	switch v := v.(type) {
	case string:
		if strings.Contains(v, "\x00") {
			return "\x00"
		}
		return v
	case json.Number:
		return v.String()
	case bool:
		if v {
			return "true"
		}
		return "false"
	}
	return "\x00"
}

// valuePattern matches a value the way a path is matched: split at "/",
// with {name} for one part and {name...} for the rest.
type valuePattern []segment

func parseValuePattern(p string) (valuePattern, error) {
	parts := strings.Split(p, "/")
	var out valuePattern
	for i, part := range parts {
		s, err := parseSegment(part)
		if err != nil {
			return nil, err
		}
		if s.rest && i != len(parts)-1 {
			return nil, fmt.Errorf("{%s...} is not the last part", s.param)
		}
		out = append(out, s)
	}
	return out, nil
}

func (p valuePattern) params() []string {
	var out []string
	for _, s := range p {
		if s.param != "" {
			out = append(out, s.param)
		}
	}
	return out
}

func (p valuePattern) match(v string) ([]Param, bool) {
	return matchSegments(p, strings.Split(v, "/"))
}

// fieldPattern is one field a rule wants and the pattern its value has to
// match.
type fieldPattern struct {
	name    string
	pattern valuePattern
}

// parseFields reads a map of field patterns in the order of the names, so
// that the parameters come in an order that does not change between reads.
func parseFields(raw map[string]string, taken []string) ([]fieldPattern, []string, error) {
	names := make([]string, 0, len(raw))
	for n := range raw {
		names = append(names, n)
	}
	slices.Sort(names)
	var (
		out    []fieldPattern
		params []string
	)
	for _, n := range names {
		if n == "" {
			return nil, nil, errors.New("an empty field name")
		}
		p, err := parseValuePattern(raw[n])
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", n, err)
		}
		for _, name := range p.params() {
			if slices.Contains(taken, name) || slices.Contains(params, name) {
				return nil, nil, fmt.Errorf("%s: {%s} is given twice", n, name)
			}
			params = append(params, name)
		}
		out = append(out, fieldPattern{name: n, pattern: p})
	}
	return out, params, nil
}

// matchFields matches every field pattern with the value value gives for
// its name.
func matchFields(fields []fieldPattern, value func(string) (string, bool)) ([]Param, bool) {
	var params []Param
	for _, f := range fields {
		v, ok := value(f.name)
		if !ok {
			return nil, false
		}
		got, ok := f.pattern.match(v)
		if !ok {
			return nil, false
		}
		params = append(params, got...)
	}
	return params, true
}
