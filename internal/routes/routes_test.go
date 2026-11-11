package routes_test

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yuanying/natsumi-sentinel/internal/routes"
)

func writeFiles(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

const basic = `
destinations:
  - name: api.example.com
    treatment: open
    default: allow
  - name: Read.Example.com.
    treatment: open
    default: deny
    ports: [443, 8443]
  - name: blocked.example.com
    treatment: deny
passthrough:
  - cidr: 192.0.2.0/24
    ports: [22, 6443]
`

func TestAnOpenDestinationIsFoundByItsNameOnPort443ByDefault(t *testing.T) {
	table, err := routes.Load(writeFiles(t, map[string]string{"routes.yaml": basic}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	dest, ok := table.Lookup("API.example.com", 443)
	if !ok {
		t.Fatal("Lookup(api.example.com, 443) found nothing")
	}
	if dest.Treatment != routes.Open || dest.Default != routes.Allow {
		t.Errorf("got %+v, want open with default allow", dest)
	}
	if _, ok := table.Lookup("api.example.com", 8443); ok {
		t.Error("Lookup(api.example.com, 8443) found a destination on a port it does not list")
	}
}

func TestNamesAreComparedWithoutCaseOrATrailingDot(t *testing.T) {
	table, err := routes.Load(writeFiles(t, map[string]string{"routes.yaml": basic}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	dest, ok := table.Lookup("read.example.com.", 8443)
	if !ok {
		t.Fatal("Lookup(read.example.com., 8443) found nothing")
	}
	if dest.Name != "read.example.com" || dest.Default != routes.Deny {
		t.Errorf("got %+v, want read.example.com with default deny", dest)
	}
}

func TestADestinationNotInTheTableIsNotFound(t *testing.T) {
	table, err := routes.Load(writeFiles(t, map[string]string{"routes.yaml": basic}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, ok := table.Lookup("unknown.example.com", 443); ok {
		t.Error("Lookup found a destination that is not in the table")
	}
}

func TestOnlyOpenDestinationsAreAnsweredInNameResolution(t *testing.T) {
	table, err := routes.Load(writeFiles(t, map[string]string{"routes.yaml": basic}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for name, want := range map[string]bool{
		"api.example.com.":    true,
		"read.example.com":    true,
		"blocked.example.com": false,
		"unknown.example.com": false,
	} {
		if got := table.Resolvable(name); got != want {
			t.Errorf("Resolvable(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestPassthroughIsDecidedByTheAddressRangeAndThePort(t *testing.T) {
	table, err := routes.Load(writeFiles(t, map[string]string{"routes.yaml": basic}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for addr, want := range map[string]bool{
		"192.0.2.10:22":          true,
		"192.0.2.10:6443":        true,
		"192.0.2.10:443":         false,
		"198.51.100.1:22":        false,
		"[2001:db8::1]:22":       false,
		"192.0.2.255:22":         true,
		"192.0.3.0:22":           false,
		"[::ffff:192.0.2.10]:22": true,
	} {
		if got := table.Passthrough(netip.MustParseAddrPort(addr)); got != want {
			t.Errorf("Passthrough(%s) = %v, want %v", addr, got, want)
		}
	}
}

func TestTheAuditSettingsDefaultTo90DaysAndA64KiBBody(t *testing.T) {
	table, err := routes.Load(writeFiles(t, map[string]string{"routes.yaml": basic}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	got := table.Audit()
	if got.Retention != 90*24*time.Hour || got.BodyLimit != 64<<10 {
		t.Errorf("Audit() = %+v, want 90 days and 65536 bytes", got)
	}
}

func TestTheAuditSettingsCanBeSet(t *testing.T) {
	table, err := routes.Load(writeFiles(t, map[string]string{
		"routes.yaml": basic,
		"audit.yaml":  "audit:\n  retentionDays: 30\n  bodyLimitBytes: 1024\n",
	}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	got := table.Audit()
	if got.Retention != 30*24*time.Hour || got.BodyLimit != 1024 {
		t.Errorf("Audit() = %+v, want 30 days and 1024 bytes", got)
	}
}

func TestFilesInTheDirectoryAreReadTogether(t *testing.T) {
	table, err := routes.Load(writeFiles(t, map[string]string{
		"a.yaml":     "destinations:\n  - name: a.example.com\n    treatment: open\n    default: allow\n",
		"b.yml":      "destinations:\n  - name: b.example.com\n    treatment: open\n    default: deny\n",
		"README.txt": "not a routing file",
	}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for _, name := range []string{"a.example.com", "b.example.com"} {
		if _, ok := table.Lookup(name, 443); !ok {
			t.Errorf("Lookup(%s) found nothing", name)
		}
	}
}

func TestHiddenEntriesThatAConfigMapMountLeavesAreSkipped(t *testing.T) {
	dir := writeFiles(t, map[string]string{"routes.yaml": basic})
	hidden := filepath.Join(dir, "..2026_11_11_00_00_00.000000001")
	if err := os.Mkdir(hidden, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".broken.yaml"), []byte("::: not yaml"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := routes.Load(dir); err != nil {
		t.Fatalf("Load: %v", err)
	}
}

func TestATableThatCannotBeUsedIsRefused(t *testing.T) {
	tests := map[string]map[string]string{
		"a directory with no routing file":         {"README.txt": "nothing"},
		"a file that is not YAML":                  {"routes.yaml": "destinations: [::"},
		"a field nobody knows":                     {"routes.yaml": "destinations:\n  - name: a.example.com\n    treatment: open\n    default: allow\n    surprise: 1\n"},
		"a treatment nobody knows":                 {"routes.yaml": "destinations:\n  - name: a.example.com\n    treatment: inspect\n"},
		"an open destination without a default":    {"routes.yaml": "destinations:\n  - name: a.example.com\n    treatment: open\n"},
		"a default that is not allow, ask or deny": {"routes.yaml": "destinations:\n  - name: a.example.com\n    treatment: open\n    default: maybe\n"},
		"a deny destination with a default":        {"routes.yaml": "destinations:\n  - name: a.example.com\n    treatment: deny\n    default: allow\n"},
		"a name given twice across files": {
			"a.yaml": "destinations:\n  - name: a.example.com\n    treatment: open\n    default: allow\n",
			"b.yaml": "destinations:\n  - name: A.example.com.\n    treatment: deny\n",
		},
		"an IP address as a name":     {"routes.yaml": "destinations:\n  - name: 192.0.2.1\n    treatment: open\n    default: allow\n"},
		"an empty name":               {"routes.yaml": "destinations:\n  - name: \"\"\n    treatment: deny\n"},
		"a port out of range":         {"routes.yaml": "destinations:\n  - name: a.example.com\n    treatment: open\n    default: allow\n    ports: [70000]\n"},
		"a range that is not a CIDR":  {"routes.yaml": "passthrough:\n  - cidr: 192.0.2.1\n    ports: [22]\n"},
		"a passthrough without ports": {"routes.yaml": "passthrough:\n  - cidr: 192.0.2.0/24\n"},
		"audit settings given twice": {
			"a.yaml": "audit:\n  retentionDays: 1\n",
			"b.yaml": "audit:\n  retentionDays: 2\n",
		},
		"a retention that is not positive":              {"routes.yaml": "audit:\n  retentionDays: 0\n"},
		"a body limit that is negative":                 {"routes.yaml": "audit:\n  bodyLimitBytes: -1\n"},
		"a rule without an operation":                   {"routes.yaml": open + "    rules:\n      - path: /a\n"},
		"a rule whose path does not start with a slash": {"routes.yaml": open + "    rules:\n      - operation: x\n        path: a/b\n"},
		"a rule with a parameter given twice":           {"routes.yaml": open + "    rules:\n      - operation: x\n        path: /{a}/{a}\n"},
		"a rest parameter that is not last":             {"routes.yaml": open + "    rules:\n      - operation: x\n        path: /{a...}/b\n"},
		"a parameter that is half a segment":            {"routes.yaml": open + "    rules:\n      - operation: x\n        path: /a{b}\n"},
		"a target that is not a parameter":              {"routes.yaml": open + "    rules:\n      - operation: x\n        path: /{a}\n        target: [b]\n"},
		"an operation name with spaces":                 {"routes.yaml": open + "    rules:\n      - operation: merge it\n"},
		"an action that is not allow, ask or deny":      {"routes.yaml": open + "    operations:\n      x: maybe\n"},
		"rules on a deny destination":                   {"routes.yaml": "destinations:\n  - name: a.example.com\n    treatment: deny\n    rules:\n      - operation: x\n"},
		"a duration that cannot be read":                {"routes.yaml": "approvals:\n  durations: [1week]\n"},
		"no durations":                                  {"routes.yaml": "approvals:\n  durations: []\n"},
		"a once lifetime that is not positive":          {"routes.yaml": "approvals:\n  once: 0s\n"},
		"approval settings given twice": {
			"a.yaml": "approvals:\n  once: 1m\n",
			"b.yaml": "approvals:\n  once: 2m\n",
		},
	}
	for name, files := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := routes.Load(writeFiles(t, files)); err == nil {
				t.Fatal("Load returned no error")
			}
		})
	}
}

const open = "destinations:\n  - name: a.example.com\n    treatment: open\n    default: ask\n"

const withRules = `
destinations:
  - name: api.example.com
    treatment: open
    default: ask
    rules:
      - operation: pulls.merge
        methods: [PUT]
        path: /repos/{owner}/{repo}/pulls/{number}/merge
        target: [owner, repo]
      - operation: contents.write
        methods: [PUT, DELETE]
        path: /repos/{owner}/{repo}/contents/{file...}
      - operation: read
        methods: [GET, HEAD]
    operations:
      read: allow
      pulls.merge: ask
      repos.delete: deny
`

func TestARuleGivesTheOperationItsParametersAndItsTarget(t *testing.T) {
	table, err := routes.Load(writeFiles(t, map[string]string{"routes.yaml": withRules}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	d, _ := table.Lookup("api.example.com", 443)
	m, ok := d.Match("PUT", "/repos/o/r/pulls/5/merge")
	if !ok {
		t.Fatal("no rule matched the merge")
	}
	if m.Operation != "pulls.merge" {
		t.Errorf("operation = %q", m.Operation)
	}
	if got := fmt.Sprint(m.Params); got != "[{owner o} {repo r} {number 5}]" {
		t.Errorf("params = %s", got)
	}
	if got := fmt.Sprint(m.Target); got != "[owner repo]" {
		t.Errorf("target = %s", got)
	}
}

func TestATargetLeftOutIsEveryParameterAndARestParameterTakesTheRestOfThePath(t *testing.T) {
	table, err := routes.Load(writeFiles(t, map[string]string{"routes.yaml": withRules}))
	if err != nil {
		t.Fatal(err)
	}
	d, _ := table.Lookup("api.example.com", 443)
	m, ok := d.Match("DELETE", "/repos/o/r/contents/docs/a/b.md")
	if !ok || m.Operation != "contents.write" {
		t.Fatalf("Match = %+v, %v", m, ok)
	}
	if got := fmt.Sprint(m.Params); got != "[{owner o} {repo r} {file docs/a/b.md}]" {
		t.Errorf("params = %s", got)
	}
	if got := fmt.Sprint(m.Target); got != "[owner repo file]" {
		t.Errorf("target = %s", got)
	}
}

func TestTheFirstRuleThatMatchesTheMethodAndPathWins(t *testing.T) {
	table, err := routes.Load(writeFiles(t, map[string]string{"routes.yaml": withRules}))
	if err != nil {
		t.Fatal(err)
	}
	d, _ := table.Lookup("api.example.com", 443)
	for _, tc := range []struct {
		method, path, want string
	}{
		{"GET", "/repos/o/r/pulls/5/merge", "read"},
		{"HEAD", "/anything", "read"},
		{"POST", "/repos/o/r/pulls/5/merge", ""},
		{"PUT", "/repos/o/r/pulls/5/merge/", ""},
		{"PUT", "/repos/o/r/pulls//merge", ""},
		{"PUT", "/repos/o/r/contents/", ""},
	} {
		m, ok := d.Match(tc.method, tc.path)
		if got := m.Operation; ok != (tc.want != "") || got != tc.want {
			t.Errorf("Match(%s %s) = %q, %v; want %q", tc.method, tc.path, got, ok, tc.want)
		}
	}
}

func TestAnOperationTakesItsActionFromTheTableOrElseTheDefault(t *testing.T) {
	table, err := routes.Load(writeFiles(t, map[string]string{"routes.yaml": withRules}))
	if err != nil {
		t.Fatal(err)
	}
	d, _ := table.Lookup("api.example.com", 443)
	for op, want := range map[string]routes.Action{
		"read":           routes.Allow,
		"pulls.merge":    routes.Ask,
		"repos.delete":   routes.Deny,
		"contents.write": routes.Ask,
		"":               routes.Ask,
	} {
		if got := d.ActionFor(op); got != want {
			t.Errorf("ActionFor(%q) = %s, want %s", op, got, want)
		}
	}
}

func TestTheApprovalSettingsDefaultToAnHourADay30DaysAndForever(t *testing.T) {
	table, err := routes.Load(writeFiles(t, map[string]string{"routes.yaml": basic}))
	if err != nil {
		t.Fatal(err)
	}
	a := table.Approvals()
	if got := fmt.Sprint(a.Durations); got != "[1h0m0s 24h0m0s 720h0m0s 0s]" {
		t.Errorf("durations = %s, want 1h, 1d, 30d and forever (0)", got)
	}
	if a.Once != 10*time.Minute || a.Pending != 24*time.Hour {
		t.Errorf("once = %s, pending = %s; want 10m and 24h", a.Once, a.Pending)
	}
}

func TestTheApprovalSettingsCanBeSetInDaysHoursAndMinutes(t *testing.T) {
	table, err := routes.Load(writeFiles(t, map[string]string{"routes.yaml": "approvals:\n  durations: [30m, 7d, forever]\n  once: 5m\n  pending: 2d\n"}))
	if err != nil {
		t.Fatal(err)
	}
	a := table.Approvals()
	if got := fmt.Sprint(a.Durations); got != "[30m0s 168h0m0s 0s]" {
		t.Errorf("durations = %s", got)
	}
	if a.Once != 5*time.Minute || a.Pending != 48*time.Hour {
		t.Errorf("once = %s, pending = %s", a.Once, a.Pending)
	}
}

func TestAMissingDirectoryIsRefused(t *testing.T) {
	if _, err := routes.Load(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("Load returned no error for a directory that does not exist")
	}
}

func TestTheErrorNamesTheFileThatIsWrong(t *testing.T) {
	_, err := routes.Load(writeFiles(t, map[string]string{"broken.yaml": "destinations: [::"}))
	if err == nil || !strings.Contains(err.Error(), "broken.yaml") {
		t.Fatalf("Load error = %v, want it to name broken.yaml", err)
	}
}
