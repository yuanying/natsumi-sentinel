// Package authd is the key keeper's side: it reads the registration of
// surrogates and upstreams, swaps a registered surrogate for its real key, and
// sends every request the gate hands it on to the upstream (docs/adr/0003).
//
// This is the only package that reads real keys. The gate reaches authd only
// through internal/authdclient and must never import this package.
package authd

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

// minSurrogateLen is the shortest surrogate accepted. A surrogate is not a
// secret, but it has to be long enough not to turn up by chance in a header
// that is not meant to carry it.
const minSurrogateLen = 16

// Config is a loaded and checked registration.
type Config struct {
	upstreams   []*upstream
	credentials []*credential
	unreadable  []UnreadableKey
}

// Credentials is how many credentials the registration holds.
func (c *Config) Credentials() int { return len(c.credentials) }

// UnreadableKey is a credential whose real key could not be read when the
// registration was loaded. Requests that use it are refused until its file
// can be read; nothing else is held up.
type UnreadableKey struct {
	// Credential is the credential's position in the registration.
	Credential int
	KeyFile    string
	// Problem says why, never with the file's content.
	Problem string
}

// UnreadableKeys are the credentials whose keys could not be read when the
// registration was loaded, in the order of the registration.
func (c *Config) UnreadableKeys() []UnreadableKey {
	return append([]UnreadableKey(nil), c.unreadable...)
}

type upstream struct {
	name  string
	ports []int
	// roots verifies the upstream's certificate; nil means the system's.
	roots *x509.CertPool
}

type placeKind int

const (
	placeBearer placeKind = iota
	placeBasic
	placeHeader
	placeQuery
)

// place is where in a request a surrogate may sit. For a bearer place,
// name is the scheme; for a header place, the canonical header name; for a
// query place, the parameter's name.
type place struct {
	kind placeKind
	name string
}

type credential struct {
	// index is the credential's position in the file. Errors and logs name
	// a credential by it, never by its surrogate.
	index     int
	surrogate string
	keyFile   string
	upstreams map[string]bool
	places    []place
}

func (c *credential) has(p place) bool {
	return slices.Contains(c.places, p)
}

type rawConfig struct {
	Upstreams   []rawUpstream   `yaml:"upstreams"`
	Credentials []rawCredential `yaml:"credentials"`
}

type rawUpstream struct {
	Name   string `yaml:"name"`
	Ports  []int  `yaml:"ports"`
	CAFile string `yaml:"ca_file"`
}

type rawCredential struct {
	Surrogate string     `yaml:"surrogate"`
	KeyFile   string     `yaml:"key_file"`
	Upstreams []string   `yaml:"upstreams"`
	Places    []rawPlace `yaml:"places"`
}

type rawPlace struct {
	Type   string `yaml:"type"`
	Scheme string `yaml:"scheme"`
	Name   string `yaml:"name"`
}

// yamlValue matches the values the YAML decoder quotes in its errors, which
// could be a surrogate put under the wrong field.
var yamlValue = regexp.MustCompile("`[^`]*`")

// LoadConfig reads and checks the registration at path. Every CA file it
// names has to be readable now: authd does not start on a registration it
// cannot use. A key file that cannot be read now does not stop the load; it
// is told by UnreadableKeys, and the requests that use it are refused, as
// they are when a key file cannot be read later. Errors name the field and
// the credential's position, never a surrogate or a key.
func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading the registration: %w", err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	var raw rawConfig
	if err := dec.Decode(&raw); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("the registration is empty")
		}
		return nil, fmt.Errorf("parsing the registration: %s", yamlValue.ReplaceAllString(err.Error(), "`...`"))
	}
	return raw.check()
}

func (raw *rawConfig) check() (*Config, error) {
	cfg := &Config{}
	if len(raw.Upstreams) == 0 {
		return nil, errors.New("no upstreams are registered")
	}
	byName := map[string]*upstream{}
	for i, ru := range raw.Upstreams {
		u, err := ru.check()
		if err != nil {
			return nil, fmt.Errorf("upstreams[%d]: %w", i, err)
		}
		if byName[u.name] != nil {
			return nil, fmt.Errorf("upstreams[%d]: upstream %s is registered twice", i, u.name)
		}
		byName[u.name] = u
		cfg.upstreams = append(cfg.upstreams, u)
	}
	seen := map[string]int{}
	for i, rc := range raw.Credentials {
		c, err := rc.check(i, byName)
		if err != nil {
			return nil, fmt.Errorf("credentials[%d]: %w", i, err)
		}
		if j, ok := seen[c.surrogate]; ok {
			return nil, fmt.Errorf("credentials[%d]: the surrogate is the same as credentials[%d]'s", i, j)
		}
		seen[c.surrogate] = i
		cfg.credentials = append(cfg.credentials, c)
		if _, err := readKey(c.keyFile); err != nil {
			cfg.unreadable = append(cfg.unreadable, UnreadableKey{Credential: i, KeyFile: c.keyFile, Problem: err.Error()})
		}
	}
	return cfg, nil
}

func (ru rawUpstream) check() (*upstream, error) {
	name := strings.ToLower(ru.Name)
	if name == "" {
		return nil, errors.New("name is required")
	}
	if net.ParseIP(name) == nil && strings.ContainsAny(name, ":/@[] \t") {
		return nil, fmt.Errorf("name %q must be a host name or an IP address, without a port", ru.Name)
	}
	u := &upstream{name: name, ports: ru.Ports}
	if len(u.ports) == 0 {
		u.ports = []int{443}
	}
	for _, p := range u.ports {
		if p < 1 || p > 65535 {
			return nil, fmt.Errorf("port %d is out of range", p)
		}
	}
	if ru.CAFile != "" {
		pem, err := os.ReadFile(ru.CAFile)
		if err != nil {
			return nil, fmt.Errorf("ca_file: %w", err)
		}
		u.roots = x509.NewCertPool()
		if !u.roots.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("ca_file %s holds no certificate", ru.CAFile)
		}
	}
	return u, nil
}

func (rc rawCredential) check(index int, upstreams map[string]*upstream) (*credential, error) {
	if !validSurrogate(rc.Surrogate) {
		return nil, fmt.Errorf("the surrogate must be at least %d visible ASCII characters with no spaces", minSurrogateLen)
	}
	if rc.KeyFile == "" {
		return nil, errors.New("key_file is required")
	}
	c := &credential{index: index, surrogate: rc.Surrogate, keyFile: rc.KeyFile, upstreams: map[string]bool{}}
	if len(rc.Upstreams) == 0 {
		return nil, errors.New("no upstreams are given for the credential")
	}
	for _, n := range rc.Upstreams {
		n = strings.ToLower(n)
		if upstreams[n] == nil {
			return nil, fmt.Errorf("upstream %s is not registered", n)
		}
		c.upstreams[n] = true
	}
	if len(rc.Places) == 0 {
		return nil, errors.New("no places are given for the credential")
	}
	for i, rp := range rc.Places {
		p, err := rp.check()
		if err != nil {
			return nil, fmt.Errorf("places[%d]: %w", i, err)
		}
		if !c.has(p) {
			c.places = append(c.places, p)
		}
	}
	return c, nil
}

func (rp rawPlace) check() (place, error) {
	switch rp.Type {
	case "bearer":
		scheme := rp.Scheme
		if scheme == "" {
			scheme = "Bearer"
		}
		if !validToken(scheme) {
			return place{}, fmt.Errorf("scheme %q is not a valid scheme", scheme)
		}
		return place{kind: placeBearer, name: scheme}, nil
	case "basic":
		return place{kind: placeBasic}, nil
	case "header":
		if rp.Name == "" {
			return place{}, errors.New("a header place needs a name")
		}
		if !validToken(rp.Name) {
			return place{}, fmt.Errorf("header name %q is not a valid header name", rp.Name)
		}
		name := http.CanonicalHeaderKey(rp.Name)
		if name == "Authorization" {
			return place{}, errors.New("use a bearer or basic place for Authorization, not a header place")
		}
		return place{kind: placeHeader, name: name}, nil
	case "query":
		if rp.Name == "" {
			return place{}, errors.New("a query place needs a name")
		}
		return place{kind: placeQuery, name: rp.Name}, nil
	default:
		return place{}, fmt.Errorf("unknown place type %q", rp.Type)
	}
}

func validSurrogate(s string) bool {
	if len(s) < minSurrogateLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// validToken reports whether s is an HTTP token (RFC 9110), as a scheme or
// a header name has to be.
func validToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
			continue
		}
		if !strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c)) {
			return false
		}
	}
	return true
}

// readKey reads a real key from its file, as it is now. The file is read on
// every use, so that a key the file's owner replaces (a Secret that kubelet
// updates, a projected token it renews) is used from the next request on.
// Surrounding white space, such as a trailing newline, is not part of the
// key. The error never holds the file's content.
func readKey(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", errors.New("cannot read the key file")
	}
	key := strings.TrimSpace(string(b))
	if key == "" {
		return "", errors.New("the key file is empty")
	}
	for i := 0; i < len(key); i++ {
		if key[i] < 0x20 || key[i] == 0x7f {
			return "", errors.New("the key file holds a control character")
		}
	}
	return key, nil
}
