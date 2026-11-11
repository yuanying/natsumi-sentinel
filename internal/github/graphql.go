package github

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/parser"

	"github.com/yuanying/natsumi-sentinel/internal/decide"
	"github.com/yuanying/natsumi-sentinel/internal/routes"
)

// maxTokens bounds the document the gate parses.
const maxTokens = 20000

// mergeFields are the mutations that merge a pull request: each has to
// name the head SHA it merges (docs/adr/0005).
var mergeFields = []string{"mergePullRequest", "enablePullRequestAutoMerge"}

type graphqlRequest struct {
	Query         *string        `json:"query"`
	Variables     map[string]any `json:"variables"`
	OperationName string         `json:"operationName"`
}

// graphql reads a GraphQL request: all queries go through as a read, one
// mutation of one field is named by the field, and anything else is
// refused with the reason (docs/adr/0005).
func (c *Connector) graphql(ctx context.Context, req decide.Request) (decide.Result, error) {
	if !req.BodyComplete {
		return refuse("the GraphQL request is longer than the gate reads (the routing table's bodyLimitBytes), so its document could not be read"), nil
	}
	if err := strictJSON(req.Body); err != nil {
		return refuse("the GraphQL request is not one JSON object the gate can read: " + err.Error()), nil
	}
	var gr graphqlRequest
	dec := json.NewDecoder(bytes.NewReader(req.Body))
	dec.UseNumber()
	if err := dec.Decode(&gr); err != nil {
		return refuse("the GraphQL request is not one JSON object the gate can read: " + err.Error()), nil
	}
	if gr.Query == nil {
		return refuse("the GraphQL request has no query"), nil
	}
	doc, err := parser.ParseQueryWithTokenLimit(&ast.Source{Input: *gr.Query}, maxTokens)
	if err != nil {
		return refuse("the GraphQL document could not be read: " + err.Error()), nil
	}
	if len(doc.Operations) == 0 {
		return refuse("the GraphQL document has no operation"), nil
	}
	var mutation *ast.OperationDefinition
	for _, op := range doc.Operations {
		switch op.Operation {
		case ast.Query:
		case ast.Mutation:
			mutation = op
		default:
			return refuse(fmt.Sprintf("the GraphQL document has a %s; the gate takes queries and mutations only", op.Operation)), nil
		}
	}
	if mutation == nil {
		return decide.Result{Read: true}, nil
	}
	if len(doc.Operations) > 1 {
		return refuse("a mutation has to be the only operation of its GraphQL document"), nil
	}
	if len(mutation.SelectionSet) != 1 {
		return refuse("a mutation has to have exactly one field at its top, written out (no fragment)"), nil
	}
	field, ok := mutation.SelectionSet[0].(*ast.Field)
	if !ok {
		return refuse("a mutation has to have exactly one field at its top, written out (no fragment)"), nil
	}
	return c.mutation(ctx, req, mutation, field, gr.Variables)
}

// mutation names the one field of a mutation and looks up what its node
// IDs are.
func (c *Connector) mutation(ctx context.Context, req decide.Request, op *ast.OperationDefinition, field *ast.Field, vars map[string]any) (decide.Result, error) {
	args := map[string]any{}
	for _, a := range field.Arguments {
		v := value(a.Value, op.VariableDefinitions, vars)
		args[a.Name] = v
		// The fields of the input object are the mutation's arguments
		// too: GitHub's mutations take all of theirs there.
		if a.Name == "input" {
			if in, ok := v.(map[string]any); ok {
				for k, iv := range in {
					if _, taken := args[k]; !taken {
						args[k] = iv
					}
				}
			}
		}
	}
	str := func(name string) string {
		s, _ := args[name].(string)
		return s
	}

	var extra []routes.Param
	if slices.Contains(mergeFields, field.Name) {
		sha := str("expectedHeadOid")
		if sha == "" {
			return refuse("a merge has to name the head SHA it merges (expectedHeadOid), so that it merges only what was looked at"), nil
		}
		extra = append(extra, routes.Param{Name: "sha", Value: sha})
	}
	if field.Name == "createRef" {
		extra = append(extra, routes.Param{Name: "ref", Value: str("name")}, routes.Param{Name: "sha", Value: str("oid")})
	}
	if field.Name == "updateRef" && str("oid") != "" {
		extra = append(extra, routes.Param{Name: "sha", Value: str("oid")})
	}

	nodes, refusal, err := c.lookUp(ctx, req, args)
	if err != nil || refusal != "" {
		return refuse(refusal), err
	}
	var (
		params, facts []routes.Param
		target        []string
	)
	if len(nodes) > 0 {
		subject := nodes[0]
		params = append(params, subject.params...)
		facts = append(facts, subject.facts...)
		for _, p := range subject.params {
			target = append(target, p.Name)
		}
	}
	params = append(params, extra...)
	for _, n := range nodes[min(1, len(nodes)):] {
		prefix := strings.TrimSuffix(n.arg, "Id") + "_"
		for _, p := range n.params {
			params = append(params, routes.Param{Name: prefix + p.Name, Value: p.Value})
		}
	}

	name := "graphql." + field.Name
	gh := req.Destination.GitHub
	if m, ok := gh.MatchField(field.Name, args, params); ok {
		name = m.Operation
		params = append(params, m.Params...)
		if m.Target != nil {
			target = m.Target
		} else {
			for _, p := range m.Params {
				target = append(target, p.Name)
			}
		}
	}
	if field.Name == "createRef" && strings.HasPrefix(str("name"), "refs/tags/") && str("oid") != "" && len(nodes) > 0 {
		owner, repo := paramValue(nodes[0].params, "owner"), paramValue(nodes[0].params, "repo")
		tf, refusal, err := c.tagFacts(ctx, req, owner, repo, str("oid"))
		if err != nil || refusal != "" {
			return refuse(refusal), err
		}
		facts = append(facts, tf...)
	}
	return decide.Result{Operations: []decide.Operation{{Name: name, Params: params, Target: target, Facts: facts}}}, nil
}

func paramValue(params []routes.Param, name string) string {
	for _, p := range params {
		if p.Name == name {
			return p.Value
		}
	}
	return ""
}

// value is an argument's value with the request's variables, or their
// defaults in the document, in place of the variables. Scalars are
// strings, as the patterns compare them.
func value(v *ast.Value, defs ast.VariableDefinitionList, vars map[string]any) any {
	if v == nil {
		return nil
	}
	switch v.Kind {
	case ast.Variable:
		if got, ok := vars[v.Raw]; ok {
			return jsonValue(got)
		}
		if def := defs.ForName(v.Raw); def != nil && def.DefaultValue != nil {
			return value(def.DefaultValue, defs, vars)
		}
		return nil
	case ast.NullValue:
		return nil
	case ast.ListValue:
		var out []any
		for _, c := range v.Children {
			out = append(out, value(c.Value, defs, vars))
		}
		return out
	case ast.ObjectValue:
		out := map[string]any{}
		for _, c := range v.Children {
			out[c.Name] = value(c.Value, defs, vars)
		}
		return out
	}
	return v.Raw
}

// jsonValue makes a variable's JSON value the same shape as value gives.
func jsonValue(v any) any {
	switch v := v.(type) {
	case json.Number:
		return v.String()
	case bool:
		if v {
			return "true"
		}
		return "false"
	case []any:
		out := make([]any, len(v))
		for i, e := range v {
			out[i] = jsonValue(e)
		}
		return out
	case map[string]any:
		out := map[string]any{}
		for k, e := range v {
			out[k] = jsonValue(e)
		}
		return out
	}
	return v
}

// strictJSON checks that b is one JSON object, with no field given twice
// in any object: the gate and GitHub must not read different values.
func strictJSON(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return errors.New("it is not one JSON object")
	}
	if err := walkObject(dec); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("it is not one JSON object")
	}
	return nil
}

// walkObject reads the rest of an object whose { has been read.
func walkObject(dec *json.Decoder) error {
	seen := map[string]bool{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := tok.(string)
		if !ok {
			return errors.New("it is not one JSON object")
		}
		if seen[key] {
			return fmt.Errorf("the field %q is given twice", key)
		}
		seen[key] = true
		if err := walkValue(dec); err != nil {
			return err
		}
	}
	_, err := dec.Token()
	return err
}

func walkValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	switch tok {
	case json.Delim('{'):
		return walkObject(dec)
	case json.Delim('['):
		for dec.More() {
			if err := walkValue(dec); err != nil {
				return err
			}
		}
		_, err := dec.Token()
		return err
	}
	return nil
}
