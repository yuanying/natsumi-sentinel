// Package certs makes the certificates the gate shows when it terminates
// TLS for an open destination: one per name, signed on the spot by the
// gate's CA (docs/adr/0002).
//
// A certificate lives a day and is kept in memory, so a name is signed
// about once a day. Nothing is written to disk: a restart signs again.
package certs

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"
)

const (
	lifetime = 24 * time.Hour
	// A certificate with less than this left is replaced, so that one
	// shown at the start of a long connection does not expire during it.
	renewBefore = time.Hour
	// Backdating covers a client whose clock runs a little behind.
	backdate = time.Hour
)

// Minter signs certificates for names with the gate's CA.
type Minter struct {
	ca     *x509.Certificate
	caKey  crypto.Signer
	caDER  []byte
	now    func() time.Time
	mu     sync.Mutex
	issued map[string]*tls.Certificate
}

// Load reads the CA's certificate and private key from PEM files. The key
// must be the certificate's.
func Load(certFile, keyFile string) (*Minter, error) {
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load the gate's CA: %w", err)
	}
	ca := pair.Leaf
	if ca == nil {
		if ca, err = x509.ParseCertificate(pair.Certificate[0]); err != nil {
			return nil, fmt.Errorf("load the gate's CA: %w", err)
		}
	}
	if !ca.IsCA {
		return nil, errors.New("load the gate's CA: the certificate is not a CA")
	}
	signer, ok := pair.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("load the gate's CA: the key cannot sign")
	}
	return &Minter{
		ca:     ca,
		caKey:  signer,
		caDER:  pair.Certificate[0],
		now:    time.Now,
		issued: map[string]*tls.Certificate{},
	}, nil
}

// SetClock replaces the clock. For tests.
func (m *Minter) SetClock(now func() time.Time) { m.now = now }

// Certificate returns a certificate for name, signing a new one when there
// is none or the one there is nears its end.
func (m *Minter) Certificate(name string) (*tls.Certificate, error) {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	now := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()
	if c, ok := m.issued[name]; ok && now.Before(c.Leaf.NotAfter.Add(-renewBefore)) {
		return c, nil
	}
	c, err := m.sign(name, now)
	if err != nil {
		return nil, err
	}
	m.issued[name] = c
	return c, nil
}

func (m *Minter) sign(name string, now time.Time) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("sign a certificate: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, fmt.Errorf("sign a certificate: %w", err)
	}
	notAfter := now.Add(lifetime)
	if notAfter.After(m.ca.NotAfter) {
		notAfter = m.ca.NotAfter
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    now.Add(-backdate),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, m.ca, &key.PublicKey, m.caKey)
	if err != nil {
		return nil, fmt.Errorf("sign a certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("sign a certificate: %w", err)
	}
	return &tls.Certificate{
		Certificate: [][]byte{der, m.caDER},
		PrivateKey:  key,
		Leaf:        leaf,
	}, nil
}
