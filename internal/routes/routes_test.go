package routes_test

import (
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
		"a directory with no routing file":      {"README.txt": "nothing"},
		"a file that is not YAML":               {"routes.yaml": "destinations: [::"},
		"a field nobody knows":                  {"routes.yaml": "destinations:\n  - name: a.example.com\n    treatment: open\n    default: allow\n    surprise: 1\n"},
		"a treatment nobody knows":              {"routes.yaml": "destinations:\n  - name: a.example.com\n    treatment: inspect\n"},
		"an open destination without a default": {"routes.yaml": "destinations:\n  - name: a.example.com\n    treatment: open\n"},
		"a default that is not allow or deny":   {"routes.yaml": "destinations:\n  - name: a.example.com\n    treatment: open\n    default: ask\n"},
		"a deny destination with a default":     {"routes.yaml": "destinations:\n  - name: a.example.com\n    treatment: deny\n    default: allow\n"},
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
		"a retention that is not positive": {"routes.yaml": "audit:\n  retentionDays: 0\n"},
		"a body limit that is negative":    {"routes.yaml": "audit:\n  bodyLimitBytes: -1\n"},
	}
	for name, files := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := routes.Load(writeFiles(t, files)); err == nil {
				t.Fatal("Load returned no error")
			}
		})
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
