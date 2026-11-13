// Package domains tells how far a destination grant for a whole domain may
// reach (docs/adr/0008 "許しの単位と期限"): up to the registrable domain,
// just below a public suffix, and never a public suffix itself.
//
// The public suffixes are those of the Public Suffix List, both its ICANN
// part and its private part (where the shared domains anyone can make
// names under are). The list is the one built into
// golang.org/x/net/publicsuffix: nothing is fetched while the gate runs,
// and the list is brought up to date with that module, by the dependency
// updates of the repository (docs/destination-grants.md).
//
// A name under no rule of the list is held to the list's default rule,
// which takes its last label as the suffix. The gate sets no narrower
// limit of its own; such a domain is told as found by the default rule.
//
// Names are expected as the routing table compares them: lower case,
// without a trailing dot.
package domains

import (
	"strings"

	"golang.org/x/net/publicsuffix"
)

// Registrable gives the registrable domain of name: the public suffix and
// one label more. byDefault is set when no rule of the list covers name,
// and the default rule decided. ok is false when name is a public suffix
// itself, or empty.
func Registrable(name string) (domain string, byDefault, ok bool) {
	if name == "" {
		return "", false, false
	}
	suffix, icann := publicsuffix.PublicSuffix(name)
	if suffix == name {
		return "", false, false
	}
	rest := strings.TrimSuffix(name, "."+suffix)
	if i := strings.LastIndexByte(rest, '.'); i >= 0 {
		rest = rest[i+1:]
	}
	// Every rule of the private part has more than one label; a suffix
	// of one label that is not ICANN's is the default rule's.
	byDefault = !icann && !strings.Contains(suffix, ".")
	return rest + "." + suffix, byDefault, true
}

// IsPublicSuffix reports whether name is a public suffix itself, by a rule
// of the list or by its default rule.
func IsPublicSuffix(name string) bool {
	suffix, _ := publicsuffix.PublicSuffix(name)
	return suffix == name
}

// Widths are the domains a grant for name can be widened to, nearest
// first: name's parents up to its registrable domain, or the registrable
// domain alone when name is one. None for a public suffix.
func Widths(name string) []string {
	reg, _, ok := Registrable(name)
	if !ok {
		return nil
	}
	if name == reg {
		return []string{reg}
	}
	var out []string
	for d := name; d != reg; {
		_, d, _ = strings.Cut(d, ".")
		out = append(out, d)
	}
	return out
}

// Covers reports whether a grant for the whole domain reaches name: the
// domain itself, and every name under it.
func Covers(domain, name string) bool {
	return name == domain || strings.HasSuffix(name, "."+domain)
}

// Suffixes are name and each of its parents, nearest first: the domains a
// grant for a whole domain would have to be for to cover name.
func Suffixes(name string) []string {
	out := []string{name}
	for d := name; ; {
		var ok bool
		if _, d, ok = strings.Cut(d, "."); !ok || d == "" {
			return out
		}
		out = append(out, d)
	}
}
