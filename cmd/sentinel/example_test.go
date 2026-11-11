package main

import (
	"bytes"
	"context"
	"testing"
)

func TestTheExampleGitHubTablePassesTheCheck(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"-check", "-config", "../../examples/github"}, &stdout, &stderr); code != 0 {
		t.Fatalf("run(-check) = %d; stderr: %s", code, stderr.String())
	}
}
