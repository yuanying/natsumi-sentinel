//go:build netns

// These tests need root in a network namespace of their own, where they
// add iptables rules. Run them with `make test-netns`, never on a host's
// own namespace.

package origdst_test

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"testing"

	"github.com/yuanying/natsumi-sentinel/internal/origdst"
)

func iptables(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command("iptables", args...).CombinedOutput(); err != nil {
		t.Fatalf("iptables %v: %v\n%s", args, err, out)
	}
}

func TestARedirectedConnectionTellsWhereItWasGoing(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("needs root in a network namespace of its own; run `make test-netns`")
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	port := ln.Addr().(*net.TCPAddr).Port
	rule := []string{"OUTPUT", "-p", "tcp", "-d", "127.0.0.2", "--dport", "443", "-j", "REDIRECT", "--to-ports", fmt.Sprint(port)}
	iptables(t, append([]string{"-t", "nat", "-A"}, rule...)...)
	t.Cleanup(func() { iptables(t, append([]string{"-t", "nat", "-D"}, rule...)...) })

	client, err := net.Dial("tcp4", "127.0.0.2:443")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	server, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Close() }()

	got, err := origdst.Lookup(server)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if want := netip.MustParseAddrPort("127.0.0.2:443"); got != want {
		t.Errorf("Lookup = %v, want %v", got, want)
	}
}

// ipv6Redirect makes ip6tables redirect tcp to dst on the loopback to port,
// or skips the test where the kernel has no IPv6 NAT.
func ipv6Redirect(t *testing.T, dst string, dport, port int) {
	t.Helper()
	if out, err := exec.Command("ip6tables", "-t", "nat", "-L", "OUTPUT").CombinedOutput(); err != nil {
		t.Skipf("skipped: no IPv6 NAT here (ip6tables -t nat: %v: %s)", err, out)
	}
	if out, err := exec.Command("ip", "-6", "addr", "add", dst+"/128", "dev", "lo", "nodad").CombinedOutput(); err != nil {
		t.Skipf("skipped: no IPv6 on the loopback (%v: %s)", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("ip", "-6", "addr", "del", dst+"/128", "dev", "lo").Run() })
	rule := []string{"OUTPUT", "-p", "tcp", "-d", dst, "--dport", fmt.Sprint(dport), "-j", "REDIRECT", "--to-ports", fmt.Sprint(port)}
	if out, err := exec.Command("ip6tables", append([]string{"-t", "nat", "-A"}, rule...)...).CombinedOutput(); err != nil {
		t.Fatalf("ip6tables %v: %v\n%s", rule, err, out)
	}
	t.Cleanup(func() { _ = exec.Command("ip6tables", append([]string{"-t", "nat", "-D"}, rule...)...).Run() })
}

func TestARedirectedIPv6ConnectionTellsWhereItWasGoing(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("needs root in a network namespace of its own; run `make test-netns`")
	}
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("skipped: no IPv6 loopback here: %v", err)
	}
	defer func() { _ = ln.Close() }()
	ipv6Redirect(t, "2001:db8::2", 443, ln.Addr().(*net.TCPAddr).Port)

	client, err := net.Dial("tcp6", "[2001:db8::2]:443")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	server, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Close() }()
	got, err := origdst.Lookup(server)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if want := netip.MustParseAddrPort("[2001:db8::2]:443"); got != want {
		t.Errorf("Lookup = %v, want %v", got, want)
	}
}
