package upstream_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yuanying/natsumi-sentinel/internal/upstream"
)

func TestInsideDomainsAreComparedLikeTheRoutingTable(t *testing.T) {
	d, err := upstream.ParseDomains([]string{"Inside.Example.", "corp.example"})
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]bool{
		"inside.example":       true,
		"API.inside.example.":  true,
		"a.b.corp.example":     true,
		"notinside.example":    false,
		"example":              false,
		"inside.example.other": false,
	} {
		if got := d.Inside(name); got != want {
			t.Errorf("Inside(%s) = %v, want %v", name, got, want)
		}
	}
}

func TestNoInsideDomainsMakeEveryNameOutside(t *testing.T) {
	var d upstream.Domains
	if d.Inside("anything.example") {
		t.Error("a name is inside with no domains")
	}
}

func TestAnInsideDomainThatIsNotANameIsAnError(t *testing.T) {
	for _, bad := range []string{"", ".", "a..b", "has space.example", "example.com:443", "https://example.com", "192.0.2.1", "2001:db8::1", strings.Repeat("a", 64) + ".example"} {
		if _, err := upstream.ParseDomains([]string{bad}); err == nil {
			t.Errorf("ParseDomains(%q) took it", bad)
		}
	}
}

func TestTheSurrogatesAreReadFromAuthdsRegistrationAndNothingElse(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "registration.yaml")
	reg := `
upstreams:
  - name: api.example.com
    ca_file: /does/not/exist.pem
credentials:
  - surrogate: surrogate-0123456789abcdef
    key_file: /does/not/exist
    upstreams: [api.example.com]
    places: [{type: bearer}]
  - surrogate: surrogate-fedcba9876543210
    key_file: /does/not/exist/either
    upstreams: [api.example.com]
    places: [{type: header, name: X-Key}]
`
	if err := os.WriteFile(path, []byte(reg), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := upstream.LoadSurrogates(path)
	if err != nil {
		t.Fatal(err)
	}
	if s.Len() != 2 {
		t.Errorf("Len = %d, want 2", s.Len())
	}
	if !s.In("Bearer surrogate-fedcba9876543210") || s.In("Bearer something-else") {
		t.Error("In does not find the surrogates read")
	}
}

func TestARegistrationThatCannotBeReadIsAnError(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		"not yaml":           "credentials: [",
		"an empty surrogate": "credentials:\n  - surrogate: \"\"\n",
	} {
		path := filepath.Join(dir, strings.ReplaceAll(name, " ", "-")+".yaml")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := upstream.LoadSurrogates(path); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	if _, err := upstream.LoadSurrogates(filepath.Join(dir, "missing.yaml")); err == nil {
		t.Error("a missing file: no error")
	}
}
