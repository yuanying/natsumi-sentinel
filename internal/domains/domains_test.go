package domains_test

import (
	"slices"
	"testing"

	"github.com/yuanying/natsumi-sentinel/internal/domains"
)

func TestTheRegistrableDomainIsJustBelowThePublicSuffix(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		byDefault  bool
	}{
		{"example.com", "example.com", false},
		{"a.b.example.com", "example.com", false},
		{"www.example.co.uk", "example.co.uk", false},
		// The private part of the list: anyone can make a name under
		// github.io.
		{"someone.github.io", "someone.github.io", false},
		{"a.someone.github.io", "someone.github.io", false},
		// No rule: the default rule takes the last label as the suffix.
		{"a.b.c.example", "c.example", true},
		{"api.ns.svc.cluster.local", "cluster.local", true},
	} {
		got, byDefault, ok := domains.Registrable(tc.name)
		if !ok || got != tc.want || byDefault != tc.byDefault {
			t.Errorf("Registrable(%q) = %q, %v, %v; want %q, %v", tc.name, got, byDefault, ok, tc.want, tc.byDefault)
		}
	}
}

func TestAPublicSuffixHasNoRegistrableDomain(t *testing.T) {
	for _, name := range []string{"com", "co.uk", "github.io", "example"} {
		if _, _, ok := domains.Registrable(name); ok {
			t.Errorf("Registrable(%q) is ok", name)
		}
		if !domains.IsPublicSuffix(name) {
			t.Errorf("IsPublicSuffix(%q) is false", name)
		}
	}
	if domains.IsPublicSuffix("example.com") {
		t.Error("example.com is a public suffix")
	}
}

func TestTheDomainsANameCanBeWidenedToAreItsParentsUpToTheRegistrableOne(t *testing.T) {
	for _, tc := range []struct {
		name string
		want []string
	}{
		{"a.b.example.com", []string{"b.example.com", "example.com"}},
		{"example.com", []string{"example.com"}},
		{"a.b.c.example", []string{"b.c.example", "c.example"}},
		{"com", nil},
	} {
		if got := domains.Widths(tc.name); !slices.Equal(got, tc.want) {
			t.Errorf("Widths(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestADomainCoversItselfAndTheNamesUnderIt(t *testing.T) {
	for _, tc := range []struct {
		name, domain string
		want         bool
	}{
		{"example.com", "example.com", true},
		{"a.example.com", "example.com", true},
		{"badexample.com", "example.com", false},
		{"example.com", "a.example.com", false},
	} {
		if got := domains.Covers(tc.domain, tc.name); got != tc.want {
			t.Errorf("Covers(%q, %q) = %v", tc.domain, tc.name, got)
		}
	}
}

func TestTheDomainsOfANameAreItAndEachOfItsParents(t *testing.T) {
	got := domains.Suffixes("a.b.example.com")
	want := []string{"a.b.example.com", "b.example.com", "example.com", "com"}
	if !slices.Equal(got, want) {
		t.Errorf("Suffixes = %v, want %v", got, want)
	}
}
