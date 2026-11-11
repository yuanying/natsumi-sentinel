package routes_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/yuanying/natsumi-sentinel/internal/routes"
)

const one = "destinations:\n  - name: one.example.com\n    treatment: open\n    default: allow\n"
const two = "destinations:\n  - name: two.example.com\n    treatment: open\n    default: allow\n"

func TestAWatcherDoesNotStartFromATableThatCannotBeRead(t *testing.T) {
	dir := writeFiles(t, map[string]string{"routes.yaml": "destinations: [::"})
	if _, err := routes.NewWatcher(dir); err == nil {
		t.Fatal("NewWatcher returned no error")
	}
}

func TestAChangedTableIsTakenOnTheNextCheck(t *testing.T) {
	dir := writeFiles(t, map[string]string{"routes.yaml": one})
	w, err := routes.NewWatcher(dir)
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "routes.yaml"), []byte(two), 0o600); err != nil {
		t.Fatal(err)
	}
	changed, err := w.Check()
	if err != nil || !changed {
		t.Fatalf("Check() = %v, %v; want true, nil", changed, err)
	}
	if _, ok := w.Current().Lookup("two.example.com", 443); !ok {
		t.Error("the new table was not taken")
	}
	if _, ok := w.Current().Lookup("one.example.com", 443); ok {
		t.Error("the old table is still in use")
	}
}

func TestAnUnchangedTableIsNotReadAgain(t *testing.T) {
	dir := writeFiles(t, map[string]string{"routes.yaml": one})
	w, err := routes.NewWatcher(dir)
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	before := w.Current()
	changed, err := w.Check()
	if err != nil || changed {
		t.Fatalf("Check() = %v, %v; want false, nil", changed, err)
	}
	if w.Current() != before {
		t.Error("the table was replaced although nothing changed")
	}
}

func TestABrokenTableKeepsThePreviousOneAndIsReportedOnce(t *testing.T) {
	dir := writeFiles(t, map[string]string{"routes.yaml": one})
	w, err := routes.NewWatcher(dir)
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "routes.yaml"), []byte("destinations: [::"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Check(); err == nil {
		t.Fatal("Check returned no error for a broken table")
	}
	if _, ok := w.Current().Lookup("one.example.com", 443); !ok {
		t.Error("the previous table was dropped")
	}
	if changed, err := w.Check(); err != nil || changed {
		t.Errorf("the same broken table was reported again: %v, %v", changed, err)
	}

	if err := os.WriteFile(filepath.Join(dir, "routes.yaml"), []byte(two), 0o600); err != nil {
		t.Fatal(err)
	}
	if changed, err := w.Check(); err != nil || !changed {
		t.Fatalf("a fixed table was not taken: %v, %v", changed, err)
	}
}

func TestADirectoryThatDisappearsKeepsThePreviousTable(t *testing.T) {
	dir := writeFiles(t, map[string]string{"routes.yaml": one})
	w, err := routes.NewWatcher(dir)
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Check(); err == nil {
		t.Fatal("Check returned no error for a directory that is gone")
	}
	if _, ok := w.Current().Lookup("one.example.com", 443); !ok {
		t.Error("the previous table was dropped")
	}
}
