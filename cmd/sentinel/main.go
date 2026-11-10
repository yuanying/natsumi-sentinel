// Command sentinel is the gate in front of the workspace's way out. It
// will take the workspace's outgoing traffic, decide on each request and
// record what goes out (docs/adr/0001, 0002).
//
// Nothing is implemented yet: the binary answers --version and otherwise
// exits with an error that says so.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/yuanying/natsumi-sentinel/internal/buildinfo"
)

const program = "sentinel"

// version is set by the build (-X main.version).
var version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet(program, flag.ContinueOnError)
	fs.SetOutput(stderr)
	showVersion := fs.Bool("version", false, "print the version and exit")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *showVersion {
		if err := buildinfo.WriteVersion(stdout, program, version); err != nil {
			return 1
		}
		return 0
	}
	_, _ = fmt.Fprintf(stderr, "%s: not implemented yet\n", program)
	return 1
}
