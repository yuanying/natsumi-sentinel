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
// match args. args holds the field's arguments, and the fields of its
// input argument beside them; only scalars are compared.
func (g *GitHub) MatchField(field string, args map[string]any) (FieldMatch, bool) {
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
		params, ok := matchFields(r.args, value)
		if !ok {
			continue
		}
		return FieldMatch{Operation: r.Operation, Params: params, Target: r.Target}, true
	}
	return FieldMatch{}, false
}

// PushMatch is a change to a ref named by a push rule.
type PushMatch struct {
	Operation string
	// Params are what the rule's ref pattern took.
	Params []Param
}

// MatchPush finds the first rule naming a change of kind to ref.
func (g *GitHub) MatchPush(kind, ref string) (PushMatch, bool) {
	for _, r := range g.Pushes {
		if !slices.Contains(r.Kinds, kind) {
			continue
		}
		var params []Param
		if r.ref != nil {
			var ok bool
			if params, ok = r.ref.match(ref); !ok {
				continue
			}
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
		Operation string            `yaml:"operation"`
		Target    []string          `yaml:"target"`
	} `yaml:"graphql"`
	Pushes []struct {
		Operation string   `yaml:"operation"`
		Kinds     []string `yaml:"kinds"`
		Ref       string   `yaml:"ref"`
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
		args, _, err := parseFields(f.Args, nil)
		if err != nil {
			return nil, fmt.Errorf("graphql[%d]: args: %w", i, err)
		}
		for _, t := range f.Target {
			if !paramName.MatchString(t) {
				return nil, fmt.Errorf("graphql[%d]: target: %q is not a parameter name", i, t)
			}
		}
		g.GraphQL = append(g.GraphQL, FieldRule{Field: f.Field, Operation: f.Operation, args: args, Target: f.Target})
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
		if p.Ref != "" {
			ref, err := parseValuePattern(p.Ref)
			if err != nil {
				return nil, fmt.Errorf("pushes[%d]: ref: %w", i, err)
			}
			for _, name := range ref.params() {
				if slices.Contains(pushParams, name) {
					return nil, fmt.Errorf("pushes[%d]: ref: {%s} is a parameter the connector gives", i, name)
				}
			}
			r.ref = ref
		}
		g.Pushes = append(g.Pushes, r)
	}
	return g, nil
}

// pushParams are the parameters the connector gives every ref of a push.
var pushParams = []string{"owner", "repo", "ref", "sha"}
