package routes_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/yuanying/natsumi-sentinel/internal/routes"
)

const withBodyRules = `
destinations:
  - name: api.example.com
    treatment: open
    default: ask
    rules:
      - operation: tag.create
        methods: [POST]
        path: /repos/{owner}/{repo}/git/refs
        body:
          ref: refs/tags/{tag...}
          sha: "{sha}"
        target: [owner, repo, tag]
      - operation: ref.create
        methods: [POST]
        path: /repos/{owner}/{repo}/git/refs
      - operation: repo.create.private
        methods: [POST]
        path: /user/repos
        body:
          private: "true"
      - operation: repo.create
        methods: [POST]
        path: /user/repos
`

func bodyDest(t *testing.T) routes.Destination {
	t.Helper()
	table, err := routes.Load(writeFiles(t, map[string]string{"routes.yaml": withBodyRules}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	d, _ := table.Lookup("api.example.com", 443)
	return d
}

func TestARuleWithBodyFieldsMatchesOnlyABodyWithThoseFieldsAndTakesTheirParameters(t *testing.T) {
	d := bodyDest(t)
	m, ok := d.MatchRequest("POST", "/repos/o/r/git/refs", routes.ParseBody([]byte(`{"ref":"refs/tags/v1.2.0","sha":"abc"}`), true))
	if !ok || m.Operation != "tag.create" {
		t.Fatalf("MatchRequest = %+v, %v", m, ok)
	}
	if got := fmt.Sprint(m.Params); got != "[{owner o} {repo r} {tag v1.2.0} {sha abc}]" {
		t.Errorf("params = %s", got)
	}
	if got := fmt.Sprint(m.Target); got != "[owner repo tag]" {
		t.Errorf("target = %s", got)
	}

	m, ok = d.MatchRequest("POST", "/repos/o/r/git/refs", routes.ParseBody([]byte(`{"ref":"refs/heads/main","sha":"abc"}`), true))
	if !ok || m.Operation != "ref.create" {
		t.Errorf("a branch: %+v, %v; want the next rule", m, ok)
	}
}

func TestABodyRuleComparesAScalarAsItsJSONText(t *testing.T) {
	d := bodyDest(t)
	for body, want := range map[string]string{
		`{"name":"x","private":true}`:   "repo.create.private",
		`{"name":"x","private":false}`:  "repo.create",
		`{"name":"x","private":"true"}`: "repo.create.private",
		`{"name":"x"}`:                  "repo.create",
	} {
		m, ok := d.MatchRequest("POST", "/user/repos", routes.ParseBody([]byte(body), true))
		if !ok || m.Operation != want {
			t.Errorf("%s: %q, %v; want %q", body, m.Operation, ok, want)
		}
	}
}

func TestABodyThatIsNotWholeOrNotAJSONObjectMatchesNoBodyRule(t *testing.T) {
	d := bodyDest(t)
	for name, b := range map[string]*routes.Body{
		"cut off":       routes.ParseBody([]byte(`{"name":"x","private":true}`), false),
		"not JSON":      routes.ParseBody([]byte(`private=true`), true),
		"an array":      routes.ParseBody([]byte(`[{"private":true}]`), true),
		"two documents": routes.ParseBody([]byte(`{"private":true} {"private":false}`), true),
		"none":          nil,
	} {
		m, ok := d.MatchRequest("POST", "/user/repos", b)
		if !ok || m.Operation != "repo.create" {
			t.Errorf("%s: %q, %v; want the rule without a body", name, m.Operation, ok)
		}
	}
}

func TestAFieldGivenTwiceInTheBodyMatchesNoBodyRule(t *testing.T) {
	d := bodyDest(t)
	m, _ := d.MatchRequest("POST", "/user/repos", routes.ParseBody([]byte(`{"private":true,"private":false}`), true))
	if m.Operation != "repo.create" {
		t.Errorf("operation = %q; a field given twice is read differently by different readers", m.Operation)
	}
}

func TestTheParametersOfARuleIncludeItsBodyFields(t *testing.T) {
	d := bodyDest(t)
	params, target, ok := d.RuleParams("tag.create")
	if !ok || fmt.Sprint(params) != "[owner repo tag sha]" || fmt.Sprint(target) != "[owner repo tag]" {
		t.Errorf("RuleParams = %v %v %v", params, target, ok)
	}
}

func TestABodyRuleIsCheckedWhenItIsRead(t *testing.T) {
	for name, rule := range map[string]string{
		"a parameter twice": "path: /repos/{owner}\n        body:\n          owner: \"{owner}\"",
		"a bad field name":  "body:\n          \"\": x",
		"a bad pattern":     "body:\n          ref: refs/{a...}/x",
	} {
		yaml := "destinations:\n  - name: api.example.com\n    treatment: open\n    default: ask\n    rules:\n      - operation: x\n        " + rule + "\n"
		if _, err := routes.Load(writeFiles(t, map[string]string{"routes.yaml": yaml})); err == nil {
			t.Errorf("%s: Load took it", name)
		}
	}
}

const withGitHub = `
destinations:
  - name: github.example.com
    treatment: open
    default: ask
    github:
      api: api.example.com
      pushes:
        - operation: git.tag.create
          kinds: [create]
          ref: refs/tags/{tag...}
        - operation: git.ref.delete
          kinds: [delete]
        - operation: git.push.force
          kinds: [force]
        - operation: git.push
          kinds: [create, update]
          ref: refs/heads/{branch...}
  - name: api.example.com
    treatment: open
    default: ask
    github:
      graphql:
        - field: createRef
          args:
            name: refs/tags/{tag...}
          operation: tag.create
          target: [owner, repo, tag]
        - field: mergePullRequest
          operation: pr.merge
`

func TestAGitHubDestinationNamesWhereTheGateAsksAndHowFieldsAndPushesAreNamed(t *testing.T) {
	table, err := routes.Load(writeFiles(t, map[string]string{"routes.yaml": withGitHub}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	git, _ := table.Lookup("github.example.com", 443)
	if git.GitHub == nil || git.GitHub.API != "api.example.com" {
		t.Fatalf("github = %+v", git.GitHub)
	}
	api, _ := table.Lookup("api.example.com", 443)
	if api.GitHub == nil || api.GitHub.API != "api.example.com" {
		t.Errorf("an API left out is the destination itself: %+v", api.GitHub)
	}

	p, ok := git.GitHub.MatchPush("create", "refs/tags/v1")
	if !ok || p.Operation != "git.tag.create" || fmt.Sprint(p.Params) != "[{tag v1}]" {
		t.Errorf("a tag: %+v %v", p, ok)
	}
	if p, ok := git.GitHub.MatchPush("update", "refs/heads/feature/x"); !ok || p.Operation != "git.push" || fmt.Sprint(p.Params) != "[{branch feature/x}]" {
		t.Errorf("a branch: %+v %v", p, ok)
	}
	if p, ok := git.GitHub.MatchPush("delete", "refs/heads/x"); !ok || p.Operation != "git.ref.delete" {
		t.Errorf("a delete: %+v %v", p, ok)
	}
	if _, ok := git.GitHub.MatchPush("update", "refs/notes/x"); ok {
		t.Error("a ref no push rule names matched")
	}

	f, ok := api.GitHub.MatchField("createRef", map[string]any{"name": "refs/tags/v2", "oid": "abc"})
	if !ok || f.Operation != "tag.create" || fmt.Sprint(f.Params) != "[{tag v2}]" || fmt.Sprint(f.Target) != "[owner repo tag]" {
		t.Errorf("createRef: %+v %v", f, ok)
	}
	if _, ok := api.GitHub.MatchField("createRef", map[string]any{"name": "refs/heads/x"}); ok {
		t.Error("a branch matched the tag rule")
	}
	if f, ok := api.GitHub.MatchField("mergePullRequest", nil); !ok || f.Operation != "pr.merge" || f.Target != nil {
		t.Errorf("mergePullRequest: %+v %v", f, ok)
	}
}

func TestAGitHubSectionIsCheckedWhenItIsRead(t *testing.T) {
	for name, section := range map[string]string{
		"an unknown kind":      "pushes:\n        - operation: x\n          kinds: [rewind]",
		"no kinds":             "pushes:\n        - operation: x",
		"a bad operation":      "pushes:\n        - operation: \"-x\"\n          kinds: [create]",
		"a field without name": "graphql:\n        - operation: x",
		"an unknown field":     "graphql:\n        - field: x\n          operation: y\n          when: z",
		"an API with a port":   "api: api.example.com:443",
	} {
		yaml := "destinations:\n  - name: api.example.com\n    treatment: open\n    default: ask\n    github:\n      " + section + "\n"
		_, err := routes.Load(writeFiles(t, map[string]string{"routes.yaml": yaml}))
		if err == nil {
			t.Errorf("%s: Load took it", name)
		} else if !strings.Contains(err.Error(), "github") && !strings.Contains(err.Error(), "line ") {
			t.Errorf("%s: the error does not name the section: %v", name, err)
		}
	}
	closed := "destinations:\n  - name: api.example.com\n    treatment: deny\n    github: {}\n"
	if _, err := routes.Load(writeFiles(t, map[string]string{"routes.yaml": closed})); err == nil {
		t.Error("a destination that is not open took a github section")
	}
}

func TestOnAGitHubDestinationTheOwnerAndRepositoryAreComparedWithoutCase(t *testing.T) {
	table, err := routes.Load(writeFiles(t, map[string]string{"routes.yaml": withGitHub + "    rules:\n      - operation: pr.merge\n        path: /repos/{owner}/{repo}/pulls/{number}/merge\n"}))
	if err != nil {
		t.Fatal(err)
	}
	api, _ := table.Lookup("api.example.com", 443)
	m, ok := api.MatchRequest("PUT", "/repos/Example/Repo.Name/pulls/5/merge", nil)
	if !ok || fmt.Sprint(m.Params) != "[{owner example} {repo repo.name} {number 5}]" {
		t.Errorf("MatchRequest = %+v %v", m, ok)
	}
	got := api.NormalizeParams([]routes.Param{{Name: "owner", Value: "Example"}, {Name: "number", Value: "A"}})
	if fmt.Sprint(got) != "[{owner example} {number A}]" {
		t.Errorf("NormalizeParams = %v", got)
	}
}
