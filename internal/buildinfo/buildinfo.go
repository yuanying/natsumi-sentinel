// Package buildinfo prints the version line that both sentinel and authd answer
// --version with, so that the two binaries in one release report themselves
// the same way.
package buildinfo

import (
	"fmt"
	"io"
)

// WriteVersion writes "<program> <version>" and a newline to w.
func WriteVersion(w io.Writer, program, version string) error {
	_, err := fmt.Fprintf(w, "%s %s\n", program, version)
	return err
}
