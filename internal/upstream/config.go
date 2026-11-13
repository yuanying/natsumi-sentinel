package upstream

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/yuanying/natsumi-sentinel/internal/routes"
)

// Domains are the inside domains: the names under them may be connected
// to private addresses (docs/adr/0008 "内側のドメインの一覧は、環境が設定で
// 渡す"). The zero Domains has none, and every name is outside.
type Domains struct {
	names []string
}

// ParseDomains takes the inside domains as the environment gives them.
// Names are compared as in the routing table: without case and without a
// trailing dot.
func ParseDomains(names []string) (Domains, error) {
	var d Domains
	for _, n := range names {
		name := routes.Normalize(n)
		if err := checkName(name); err != nil {
			return Domains{}, fmt.Errorf("inside domain %q: %w", n, err)
		}
		d.names = append(d.names, name)
	}
	return d, nil
}

// Inside reports whether name is an inside domain or a name under one.
func (d Domains) Inside(name string) bool {
	name = routes.Normalize(name)
	for _, dom := range d.names {
		if name == dom || strings.HasSuffix(name, "."+dom) {
			return true
		}
	}
	return false
}

// checkName holds name to the shape of a DNS name: dot separated labels
// of letters, digits, '-' and '_', none empty or longer than 63 bytes, at
// most 253 bytes in all, and not an IP address.
func checkName(name string) error {
	switch {
	case name == "":
		return errors.New("empty")
	case len(name) > 253:
		return errors.New("longer than 253 bytes")
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return errors.New("an IP address, not a name")
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 {
			return errors.New("a label is empty or longer than 63 bytes")
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' && r != '_' {
				return fmt.Errorf("%q is not a letter, a digit, '-' or '_'", r)
			}
		}
	}
	return nil
}

// Surrogates are the surrogates registered with authd. The gate knows them
// only to refuse a request that carries one where nothing swaps it: a
// surrogate is not a secret (docs/adr/0003), and the gate is never given a
// key.
type Surrogates struct {
	values []string
}

// NewSurrogates makes Surrogates of the values given.
func NewSurrogates(values []string) Surrogates {
	return Surrogates{values: append([]string(nil), values...)}
}

// Len is how many surrogates there are.
func (s Surrogates) Len() int { return len(s.values) }

// In reports whether any surrogate is in v, whole or as a part.
func (s Surrogates) In(v string) bool {
	for _, sur := range s.values {
		if strings.Contains(v, sur) {
			return true
		}
	}
	return false
}

// LoadSurrogates reads the surrogates from authd's registration
// (docs/authd-registration.md), and nothing else from it: the key files it
// names are not opened. Whether the registration is otherwise sound is
// authd's to check. An error never holds a surrogate.
func LoadSurrogates(path string) (Surrogates, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Surrogates{}, fmt.Errorf("authd's registration: %w", err)
	}
	var raw struct {
		Credentials []struct {
			Surrogate string `yaml:"surrogate"`
		} `yaml:"credentials"`
	}
	if err := yaml.Unmarshal(b, &raw); err != nil {
		return Surrogates{}, errors.New("authd's registration is not YAML of the registration's shape")
	}
	var values []string
	for i, c := range raw.Credentials {
		if c.Surrogate == "" {
			return Surrogates{}, fmt.Errorf("authd's registration: credentials[%d] has no surrogate", i)
		}
		values = append(values, c.Surrogate)
	}
	return Surrogates{values: values}, nil
}
