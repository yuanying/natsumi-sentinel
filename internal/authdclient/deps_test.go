package authdclient_test

import (
	"os/exec"
	"strings"
	"testing"
)

// The gate's binary must not carry the code that reads the real keys
// (docs/adr/0001, CLAUDE.md). That code lives in internal/authd; the gate
// reaches authd only through this package.
const keyReadingPackage = "github.com/yuanying/natsumi-sentinel/internal/authd"

func TestTheGateAndThisPackageDoNotDependOnAuthdsKeyReadingCode(t *testing.T) {
	gobin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("the go command is not on PATH")
	}
	for _, pkg := range []string{".", "../../cmd/sentinel"} {
		out, err := exec.Command(gobin, "list", "-deps", "-f", "{{.ImportPath}}", pkg).Output()
		if err != nil {
			t.Fatalf("go list -deps %s: %v", pkg, err)
		}
		for _, dep := range strings.Fields(string(out)) {
			if dep == keyReadingPackage || strings.HasPrefix(dep, keyReadingPackage+"/") {
				t.Errorf("%s depends on %s", pkg, dep)
			}
		}
	}
}
