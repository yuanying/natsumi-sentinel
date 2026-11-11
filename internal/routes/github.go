package routes

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// GitHub is a destination's GitHub section: the destination's requests are
// read by the GitHub connector (docs/adr/0005, docs/github.md), which
// names GraphQL mutations by their field and git pushes by their refs.
type GitHub struct {
	// API is the name the gate asks its own questions on (the REST and
	// GraphQL API). It is the destination itself unless given.
	API string
	// GraphQL names a mutation by its field, first match first.
	GraphQL []FieldRule
	// Pushes name each ref a push changes, first match first.
	Pushes []PushRule
}

// FieldRule names a GraphQL mutation by the name of its one field and,
// when it has any, the values of its arguments.
type FieldRule struct {
	Field     string
	Operation string
	args      []fieldPattern
	// on are patterns on the parameters of what the mutation is on, as
	// the connector looked them up.
	on []fieldPattern
	// Target names the parameters that make the target. Nil leaves it to
	// the connector: the parameters of what the mutation is on.
	Target []string
}

// PushRule names a change to one ref in a push.
type PushRule struct {
	Operation string
	// Kinds are the kinds of change it names (PushKinds).
	Kinds []string
	ref   valuePattern
	// repository matches "owner/repo".
	repository valuePattern
}

// PushKinds are the kinds of change a push makes to a ref.
var PushKinds = []string{"create", "update", "force", "delete"}

// FieldMatch is a mutation named by a field rule.
type FieldMatch struct {
	Operation string
	// Params are what the rule's argument patterns took.
	Params []Param
	Target []string
}

// MatchField finds the first rule for field whose argument patterns all
// match args and whose patterns on what the mutation is on all match
// params. args holds the field's arguments, and the fields of its input
// argument beside them; only scalars are compared.
func (g *GitHub) MatchField(field string, args map[string]any, params []Param) (FieldMatch, bool) {
	param := func(name string) (string, bool) {
		for _, p := range params {
			if p.Name == name {
				return p.Value, true
			}
		}
		return "", false
	}
	value := func(name string) (string, bool) {
		v, ok := args[name]
		if !ok {
			return "", false
		}
		switch v := v.(type) {
		case string:
			return v, true
		case bool, int64, float64:
			return fmt.Sprint(v), true
		}
		return "", false
	}
	for _, r := range g.GraphQL {
		if r.Field != field {
			continue
		}
		got, ok := matchFields(r.args, value)
		if !ok {
			continue
		}
		more, ok := matchFields(r.on, param)
		if !ok {
			continue
		}
		return FieldMatch{Operation: r.Operation, Params: append(got, more...), Target: r.Target}, true
	}
	return FieldMatch{}, false
}

// PushMatch is a change to a ref named by a push rule.
type PushMatch struct {
	Operation string
	// Params are what the rule's ref pattern took.
	Params []Param
}

// MatchPush finds the first rule naming a change of kind to ref in the
// repository ("owner/repo").
func (g *GitHub) MatchPush(kind, repository, ref string) (PushMatch, bool) {
	for _, r := range g.Pushes {
		if !slices.Contains(r.Kinds, kind) {
			continue
		}
		var params []Param
		if r.repository != nil {
			got, ok := r.repository.match(repository)
			if !ok {
				continue
			}
			params = got
		}
		if r.ref != nil {
			got, ok := r.ref.match(ref)
			if !ok {
				continue
			}
			params = append(params, got...)
		}
		return PushMatch{Operation: r.Operation, Params: params}, true
	}
	return PushMatch{}, false
}

type rawGitHub struct {
	API     string `yaml:"api"`
	GraphQL []struct {
		Field     string            `yaml:"field"`
		Args      map[string]string `yaml:"args"`
		On        map[string]string `yaml:"on"`
		Operation string            `yaml:"operation"`
		Target    []string          `yaml:"target"`
	} `yaml:"graphql"`
	Pushes []struct {
		Operation  string   `yaml:"operation"`
		Kinds      []string `yaml:"kinds"`
		Repository string   `yaml:"repository"`
		Ref        string   `yaml:"ref"`
	} `yaml:"pushes"`
}

func (rg *rawGitHub) check(self string) (*GitHub, error) {
	g := &GitHub{API: Normalize(rg.API)}
	if g.API == "" {
		g.API = self
	}
	if strings.ContainsAny(g.API, ":/") {
		return nil, fmt.Errorf("api: %q is a name, without a port or a path", rg.API)
	}
	if _, err := netip.ParseAddr(g.API); err == nil {
		return nil, fmt.Errorf("api: %s is an address; it has to be a name", g.API)
	}
	for i, f := range rg.GraphQL {
		if f.Field == "" {
			return nil, fmt.Errorf("graphql[%d]: field: required", i)
		}
		if !operationName.MatchString(f.Operation) {
			return nil, fmt.Errorf("graphql[%d]: operation: %q is not an operation name", i, f.Operation)
		}
		args, taken, err := parseFields(f.Args, nil)
		if err != nil {
			return nil, fmt.Errorf("graphql[%d]: args: %w", i, err)
		}
		on, _, err := parseFields(f.On, taken)
		if err != nil {
			return nil, fmt.Errorf("graphql[%d]: on: %w", i, err)
		}
		for _, t := range f.Target {
			if !paramName.MatchString(t) {
				return nil, fmt.Errorf("graphql[%d]: target: %q is not a parameter name", i, t)
			}
		}
		g.GraphQL = append(g.GraphQL, FieldRule{Field: f.Field, Operation: f.Operation, args: args, on: on, Target: f.Target})
	}
	for i, p := range rg.Pushes {
		if !operationName.MatchString(p.Operation) {
			return nil, fmt.Errorf("pushes[%d]: operation: %q is not an operation name", i, p.Operation)
		}
		if len(p.Kinds) == 0 {
			return nil, fmt.Errorf("pushes[%d]: kinds: at least one of %s", i, strings.Join(PushKinds, ", "))
		}
		for _, k := range p.Kinds {
			if !slices.Contains(PushKinds, k) {
				return nil, fmt.Errorf("pushes[%d]: kinds: %q is not one of %s", i, k, strings.Join(PushKinds, ", "))
			}
		}
		r := PushRule{Operation: p.Operation, Kinds: p.Kinds}
		var taken []string
		for _, f := range []struct {
			name, pattern string
			to            *valuePattern
		}{{"repository", p.Repository, &r.repository}, {"ref", p.Ref, &r.ref}} {
			if f.pattern == "" {
				continue
			}
			vp, err := parseValuePattern(f.pattern)
			if err != nil {
				return nil, fmt.Errorf("pushes[%d]: %s: %w", i, f.name, err)
			}
			for _, name := range vp.params() {
				if slices.Contains(pushParams, name) || slices.Contains(taken, name) {
					return nil, fmt.Errorf("pushes[%d]: %s: {%s} is a parameter given already", i, f.name, name)
				}
				taken = append(taken, name)
			}
			*f.to = vp
		}
		g.Pushes = append(g.Pushes, r)
	}
	return g, nil
}

// pushParams are the parameters the connector gives every ref of a push.
var pushParams = []string{"owner", "repo", "ref", "sha"}
