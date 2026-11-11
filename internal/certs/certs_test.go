package certs_test

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yuanying/natsumi-sentinel/internal/certs"
	"github.com/yuanying/natsumi-sentinel/internal/testca"
)

func TestACertificateMadeForANameIsTrustedThroughTheGatesCA(t *testing.T) {
	ca := testca.New(t)
	m, err := certs.Load(ca.CertFile, ca.KeyFile)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	c, err := m.Certificate("api.example.com")
	if err != nil {
		t.Fatalf("Certificate: %v", err)
	}
	if _, err := c.Leaf.Verify(x509.VerifyOptions{DNSName: "api.example.com", Roots: ca.Pool()}); err != nil {
		t.Errorf("the certificate does not verify for api.example.com: %v", err)
	}
	if err := c.Leaf.VerifyHostname("other.example.com"); err == nil {
		t.Error("the certificate is also good for another name")
	}
	if c.Leaf.IsCA {
		t.Error("the certificate made for a name is a CA")
	}
}

func TestTheSameNameGetsTheSameCertificateUntilItNearsItsEnd(t *testing.T) {
	ca := testca.New(t)
	m, err := certs.Load(ca.CertFile, ca.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	m.SetClock(func() time.Time { return now })
	a, err := m.Certificate("API.example.com")
	if err != nil {
		t.Fatal(err)
	}
	b, err := m.Certificate("api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Error("the same name was given a new certificate")
	}
	if life := a.Leaf.NotAfter.Sub(now); life < 23*time.Hour || life > 25*time.Hour {
		t.Errorf("the certificate lives %v, want about a day", life)
	}

	now = now.Add(23*time.Hour + 30*time.Minute)
	c, err := m.Certificate("api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if c == a {
		t.Error("a certificate with less than an hour left was given again")
	}
}

func TestACertificateDoesNotOutliveTheCA(t *testing.T) {
	ca := testca.New(t)
	m, err := certs.Load(ca.CertFile, ca.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	m.SetClock(func() time.Time { return ca.Cert.NotAfter.Add(-2 * time.Hour) })
	c, err := m.Certificate("api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if c.Leaf.NotAfter.After(ca.Cert.NotAfter) {
		t.Errorf("the certificate ends %v, after the CA (%v)", c.Leaf.NotAfter, ca.Cert.NotAfter)
	}
}

func TestACAThatCannotBeUsedIsRefused(t *testing.T) {
	ca := testca.New(t)
	other := testca.New(t)
	dir := t.TempDir()
	junk := filepath.Join(dir, "junk")
	if err := os.WriteFile(junk, []byte("not PEM"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := map[string][2]string{
		"a missing certificate":         {filepath.Join(dir, "missing"), ca.KeyFile},
		"a missing key":                 {ca.CertFile, filepath.Join(dir, "missing")},
		"a certificate that is not PEM": {junk, ca.KeyFile},
		"a key that is not PEM":         {ca.CertFile, junk},
		"a key of another CA":           {ca.CertFile, other.KeyFile},
	}
	for name, files := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := certs.Load(files[0], files[1]); err == nil {
				t.Fatal("Load returned no error")
			}
		})
	}
}
