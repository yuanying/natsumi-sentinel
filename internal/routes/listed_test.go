package routes_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/yuanying/natsumi-sentinel/internal/routes"
)

func TestANameIsListedWhateverItsTreatmentAndPorts(t *testing.T) {
	dir := t.TempDir()
	table := `
destinations:
  - name: open.example.com
    treatment: open
    default: allow
    ports: [8443]
  - name: closed.example.com
    treatment: deny
`
	if err := os.WriteFile(filepath.Join(dir, "routes.yaml"), []byte(table), 0o600); err != nil {
		t.Fatal(err)
	}
	tbl, err := routes.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]bool{
		"open.example.com":    true,
		"Closed.Example.com.": true,
		"other.example.com":   false,
		"":                    false,
	} {
		if got := tbl.Listed(name); got != want {
			t.Errorf("Listed(%q) = %v, want %v", name, got, want)
		}
	}
}
