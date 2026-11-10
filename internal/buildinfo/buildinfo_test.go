package buildinfo_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/yuanying/natsumi-sentinel/internal/buildinfo"
)

func TestWriteVersionLeavesTheProgramAndItsVersionOnOneLine(t *testing.T) {
	tests := []struct {
		name    string
		program string
		version string
		want    string
	}{
		{name: "a released build", program: "sentinel", version: "v1.2.3", want: "sentinel v1.2.3\n"},
		{name: "a build without -X main.version", program: "authd", version: "dev", want: "authd dev\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			if err := buildinfo.WriteVersion(&out, tt.program, tt.version); err != nil {
				t.Fatalf("WriteVersion: %v", err)
			}
			if got := out.String(); got != tt.want {
				t.Errorf("WriteVersion wrote %q, want %q", got, tt.want)
			}
		})
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("closed") }

func TestWriteVersionReportsAWriterThatFails(t *testing.T) {
	if err := buildinfo.WriteVersion(failingWriter{}, "sentinel", "dev"); err == nil {
		t.Fatal("WriteVersion returned nil for a writer that fails")
	}
}
