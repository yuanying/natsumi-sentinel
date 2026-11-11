package authd_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yuanying/natsumi-sentinel/internal/authd"
)

// Values that must never show up in an error. They are made up for the tests.
const (
	testSurrogate = "surrogate-0123456789abcdef"
	testKey       = "real-key-for-the-test-only"
)

type files struct {
	dir string
}

func newFiles(t *testing.T) files {
	t.Helper()
	return files{dir: t.TempDir()}
}

func (f files) write(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(f.dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// config writes a registration with one upstream and one credential, with
// replace applied to the text, and returns its path.
func (f files) config(t *testing.T, replace ...string) string {
	t.Helper()
	key := f.write(t, "key", testKey+"\n")
	text := strings.Join([]string{
		"upstreams:",
		"  - name: api.example.com",
		"  - name: packages.example.com",
		"credentials:",
		"  - surrogate: " + testSurrogate,
		"    key_file: " + key,
		"    upstreams: [api.example.com]",
		"    places:",
		"      - type: bearer",
		"",
	}, "\n")
	text = strings.NewReplacer(replace...).Replace(text)
	return f.write(t, "authd.yaml", text)
}

func TestAWellFormedRegistrationLoads(t *testing.T) {
	f := newFiles(t)
	if _, err := authd.LoadConfig(f.config(t)); err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
}

func TestEveryKindOfPlaceLoads(t *testing.T) {
	f := newFiles(t)
	path := f.config(t, "      - type: bearer\n", strings.Join([]string{
		"      - type: bearer",
		"        scheme: token",
		"      - type: basic",
		"      - type: header",
		"        name: X-Api-Key",
		"      - type: query",
		"        name: api_key",
		"",
	}, "\n"))
	if _, err := authd.LoadConfig(path); err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
}

func TestARegistrationThatCannotBeUsedDoesNotLoad(t *testing.T) {
	cases := []struct {
		name    string
		replace []string
		want    string
	}{
		{"an unknown field", []string{"  - name: api.example.com\n", "  - name: api.example.com\n    colour: blue\n"}, "colour"},
		{"no upstreams", []string{"  - name: api.example.com\n  - name: packages.example.com\n", "", "    upstreams: [api.example.com]\n", "    upstreams: []\n"}, "upstream"},
		{"an upstream without a name", []string{"  - name: packages.example.com\n", "  - ports: [443]\n"}, "name"},
		{"the same upstream twice", []string{"packages.example.com", "API.example.com"}, "api.example.com"},
		{"a port out of range", []string{"  - name: packages.example.com\n", "  - name: packages.example.com\n    ports: [70000]\n"}, "port"},
		{"a name with a port in it", []string{"  - name: packages.example.com\n", "  - name: packages.example.com:443\n"}, "name"},
		{"a credential for an upstream that is not registered", []string{"[api.example.com]", "[nowhere.example.com]"}, "nowhere.example.com"},
		{"a credential with no upstreams", []string{"[api.example.com]", "[]"}, "upstream"},
		{"a credential with no places", []string{"    places:\n      - type: bearer\n", "    places: []\n"}, "place"},
		{"an unknown kind of place", []string{"type: bearer", "type: cookie"}, "cookie"},
		{"a header place without a name", []string{"type: bearer", "type: header"}, "name"},
		{"a header place for Authorization", []string{"      - type: bearer\n", "      - type: header\n        name: authorization\n"}, "Authorization"},
		{"a query place without a name", []string{"type: bearer", "type: query"}, "name"},
		{"a short surrogate", []string{testSurrogate, "short"}, "surrogate"},
		{"a surrogate with a space", []string{testSurrogate, "\"surrogate with spaces in it\""}, "surrogate"},
		{"no key file", []string{"    key_file: ", "    # key_file: "}, "key_file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFiles(t)
			_, err := authd.LoadConfig(f.config(t, tc.replace...))
			if err == nil {
				t.Fatal("LoadConfig succeeded")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
			if strings.Contains(err.Error(), testSurrogate) || strings.Contains(err.Error(), testKey) {
				t.Errorf("error %q holds a surrogate or a key", err)
			}
		})
	}
}

func TestTheSameSurrogateTwiceDoesNotLoadAndTheErrorDoesNotShowIt(t *testing.T) {
	f := newFiles(t)
	key := f.write(t, "key", testKey)
	path := f.write(t, "authd.yaml", strings.Join([]string{
		"upstreams:",
		"  - name: api.example.com",
		"credentials:",
		"  - surrogate: " + testSurrogate,
		"    key_file: " + key,
		"    upstreams: [api.example.com]",
		"    places: [{type: bearer}]",
		"  - surrogate: " + testSurrogate,
		"    key_file: " + key,
		"    upstreams: [api.example.com]",
		"    places: [{type: basic}]",
		"",
	}, "\n"))
	_, err := authd.LoadConfig(path)
	if err == nil {
		t.Fatal("LoadConfig succeeded")
	}
	if strings.Contains(err.Error(), testSurrogate) {
		t.Errorf("error %q shows the surrogate", err)
	}
}

func TestAKeyFileThatCannotBeReadDoesNotStopTheLoadAndIsToldByItsPosition(t *testing.T) {
	for name, spoil := range map[string]func(t *testing.T, f files){
		"missing": func(t *testing.T, f files) {
			if err := os.Remove(filepath.Join(f.dir, "key")); err != nil {
				t.Fatal(err)
			}
		},
		"empty":             func(t *testing.T, f files) { f.write(t, "key", "\n") },
		"control character": func(t *testing.T, f files) { f.write(t, "key", testKey+"\x01") },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFiles(t)
			path := f.config(t)
			spoil(t, f)
			cfg, err := authd.LoadConfig(path)
			if err != nil {
				t.Fatalf("LoadConfig: %v", err)
			}
			got := cfg.UnreadableKeys()
			if len(got) != 1 || got[0].Credential != 0 {
				t.Fatalf("UnreadableKeys = %+v, want the credential at 0", got)
			}
			if got[0].KeyFile != filepath.Join(f.dir, "key") {
				t.Errorf("KeyFile = %q, want the file's path", got[0].KeyFile)
			}
			if got[0].Problem == "" || strings.Contains(got[0].Problem, testKey) {
				t.Errorf("Problem = %q, want why, without the key", got[0].Problem)
			}
		})
	}
}

func TestKeyFilesThatCanBeReadAreNotTold(t *testing.T) {
	f := newFiles(t)
	cfg, err := authd.LoadConfig(f.config(t))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if got := cfg.UnreadableKeys(); len(got) != 0 {
		t.Errorf("UnreadableKeys = %+v, want none", got)
	}
}

func TestACAFileThatHoldsNoCertificateStopsTheLoad(t *testing.T) {
	f := newFiles(t)
	ca := f.write(t, "ca.pem", "not a certificate")
	path := f.config(t, "  - name: api.example.com\n", "  - name: api.example.com\n    ca_file: "+ca+"\n")
	if _, err := authd.LoadConfig(path); err == nil {
		t.Fatal("LoadConfig succeeded")
	}
}

func TestAMissingOrBrokenConfigFileStopsTheLoad(t *testing.T) {
	f := newFiles(t)
	if _, err := authd.LoadConfig(filepath.Join(f.dir, "none.yaml")); err == nil {
		t.Error("LoadConfig of a missing file succeeded")
	}
	if _, err := authd.LoadConfig(f.write(t, "broken.yaml", "upstreams: [")); err == nil {
		t.Error("LoadConfig of broken YAML succeeded")
	}
	if _, err := authd.LoadConfig(f.write(t, "empty.yaml", "")); err == nil {
		t.Error("LoadConfig of an empty file succeeded")
	}
}
