package origdst_test

import (
	"net"
	"testing"

	"github.com/yuanying/natsumi-sentinel/internal/origdst"
)

func TestAConnectionThatIsNotTCPHasNoOriginalDestination(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = a.Close(); _ = b.Close() }()
	if _, err := origdst.Lookup(a); err == nil {
		t.Fatal("Lookup returned no error for a pipe")
	}
}
