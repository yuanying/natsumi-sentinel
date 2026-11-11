// Package routes reads the gate's routing table: for each destination,
// whether the gate opens it, passes it through or denies it (docs/adr/0002),
// and the settings of the audit records (docs/adr/0006). The format is
// described in docs/routes.md.
//
// A table is read from every YAML file in one directory, so that it can be
// mounted from a ConfigMap and read again without recreating the Pod
// (docs/adr/0004).
package routes

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// Treatment is what the gate does with a destination.
type Treatment string

const (
	// Open terminates TLS, reads each request and decides on it.
	Open Treatment = "open"
	// Closed lets nothing through. A destination not in the table is
	// treated the same way.
	Closed Treatment = "deny"
)

// Action is what the table says to do with a request: let it through, ask
// the owner, or refuse it (docs/adr/0004).
type Action string

const (
	Allow Action = "allow"
	Ask   Action = "ask"
	Deny  Action = "deny"
)

// Destination is one name in the table.
type Destination struct {
	Name      string
	Treatment Treatment
	// Default is the action for requests no rule decides on. Empty unless
	// the destination is open.
	Default Action
	Ports   []uint16
	// Rules match requests to operations, first match first.
	Rules []Rule
	// Operations give the action for an operation by its name.
	Operations map[string]Action
}

// AllowsPort reports whether the destination is reached on port.
func (d Destination) AllowsPort(port uint16) bool {
	return slices.Contains(d.Ports, port)
}

// AuditSettings are the parts of the table that shape the audit records.
type AuditSettings struct {
	// Retention is how long a record is kept.
	Retention time.Duration
	// BodyLimit is how many bytes of a request body are kept in a record.
	BodyLimit int64
}

const (
	defaultRetentionDays = 90
	defaultBodyLimit     = 64 << 10
)

type passthrough struct {
	prefix netip.Prefix
	ports  []uint16
}

// Table is one routing table, read in full. A Table is never changed after
// it is read, so it can be shared between goroutines.
type Table struct {
	destinations map[string]Destination
	passthrough  []passthrough
	audit        AuditSettings
	approvals    ApprovalSettings
}

// Lookup returns the destination named name, if the table lists it on
// port. Names are compared without case and without a trailing dot.
func (t *Table) Lookup(name string, port uint16) (Destination, bool) {
	d, ok := t.destinations[Normalize(name)]
	if !ok || !d.AllowsPort(port) {
		return Destination{}, false
	}
	return d, true
}

// Resolvable reports whether the gate answers name in name resolution with
// the real addresses. Only open destinations are.
func (t *Table) Resolvable(name string) bool {
	d, ok := t.destinations[Normalize(name)]
	return ok && d.Treatment == Open
}

// Passthrough reports whether a connection to addr goes straight through.
func (t *Table) Passthrough(addr netip.AddrPort) bool {
	ip := addr.Addr().Unmap()
	for _, p := range t.passthrough {
		if p.prefix.Contains(ip) && slices.Contains(p.ports, addr.Port()) {
			return true
		}
	}
	return false
}

// Audit returns the audit settings.
func (t *Table) Audit() AuditSettings { return t.audit }

// Approvals returns the approval settings.
func (t *Table) Approvals() ApprovalSettings { return t.approvals }

// Normalize gives the form names are compared in: lower case, without a
// trailing dot.
func Normalize(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

// The shape of one file.
type file struct {
	Destinations []struct {
		Name       string            `yaml:"name"`
		Treatment  string            `yaml:"treatment"`
		Default    string            `yaml:"default"`
		Ports      []int             `yaml:"ports"`
		Rules      []rawRule         `yaml:"rules"`
		Operations map[string]string `yaml:"operations"`
	} `yaml:"destinations"`
	Passthrough []struct {
		CIDR  string `yaml:"cidr"`
		Ports []int  `yaml:"ports"`
	} `yaml:"passthrough"`
	Audit *struct {
		RetentionDays  *int   `yaml:"retentionDays"`
		BodyLimitBytes *int64 `yaml:"bodyLimitBytes"`
	} `yaml:"audit"`
	Approvals *rawApprovals `yaml:"approvals"`
}

// Load reads every *.yaml and *.yml file in dir. Entries whose names start
// with a dot (what a ConfigMap mount leaves beside the keys) are skipped.
// Load fails unless there is at least one such file and every one of them is
// valid.
func Load(dir string) (*Table, error) {
	files, err := readDir(dir)
	if err != nil {
		return nil, err
	}
	return parse(files)
}

type source struct {
	name string
	body []byte
}

func readDir(dir string) ([]source, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read the routing directory: %w", err)
	}
	var files []source
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		if ext := filepath.Ext(name); ext != ".yaml" && ext != ".yml" {
			continue
		}
		body, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", name, err)
		}
		files = append(files, source{name: name, body: body})
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no *.yaml or *.yml file in the routing directory %s", dir)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].name < files[j].name })
	return files, nil
}

func parse(files []source) (*Table, error) {
	t := &Table{
		destinations: map[string]Destination{},
		audit: AuditSettings{
			Retention: defaultRetentionDays * 24 * time.Hour,
			BodyLimit: defaultBodyLimit,
		},
		approvals: defaultApprovals(),
	}
	auditFrom, approvalsFrom := "", ""
	for _, src := range files {
		var f file
		dec := yaml.NewDecoder(bytes.NewReader(src.body))
		dec.KnownFields(true)
		if err := dec.Decode(&f); err != nil && !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("%s: %w", src.name, err)
		}
		for i, d := range f.Destinations {
			dest, err := destination(d.Name, d.Treatment, d.Default, d.Ports)
			if err == nil {
				err = dest.addRules(d.Rules, d.Operations)
			}
			if err != nil {
				return nil, fmt.Errorf("%s: destinations[%d]: %w", src.name, i, err)
			}
			if _, dup := t.destinations[dest.Name]; dup {
				return nil, fmt.Errorf("%s: destinations[%d]: %s is listed more than once", src.name, i, dest.Name)
			}
			t.destinations[dest.Name] = dest
		}
		for i, p := range f.Passthrough {
			prefix, err := netip.ParsePrefix(p.CIDR)
			if err != nil {
				return nil, fmt.Errorf("%s: passthrough[%d]: cidr: %w", src.name, i, err)
			}
			if len(p.Ports) == 0 {
				return nil, fmt.Errorf("%s: passthrough[%d]: ports: at least one port is required", src.name, i)
			}
			ports, err := portList(p.Ports)
			if err != nil {
				return nil, fmt.Errorf("%s: passthrough[%d]: %w", src.name, i, err)
			}
			t.passthrough = append(t.passthrough, passthrough{prefix: prefix.Masked(), ports: ports})
		}
		if f.Audit != nil {
			if auditFrom != "" {
				return nil, fmt.Errorf("%s: audit: already given in %s", src.name, auditFrom)
			}
			auditFrom = src.name
			if r := f.Audit.RetentionDays; r != nil {
				if *r <= 0 {
					return nil, fmt.Errorf("%s: audit: retentionDays must be positive", src.name)
				}
				t.audit.Retention = time.Duration(*r) * 24 * time.Hour
			}
			if b := f.Audit.BodyLimitBytes; b != nil {
				if *b < 0 {
					return nil, fmt.Errorf("%s: audit: bodyLimitBytes must not be negative", src.name)
				}
				t.audit.BodyLimit = *b
			}
		}
		if f.Approvals != nil {
			if approvalsFrom != "" {
				return nil, fmt.Errorf("%s: approvals: already given in %s", src.name, approvalsFrom)
			}
			approvalsFrom = src.name
			if err := f.Approvals.apply(&t.approvals); err != nil {
				return nil, fmt.Errorf("%s: approvals: %w", src.name, err)
			}
		}
	}
	return t, nil
}

func destination(name, treatment, def string, ports []int) (Destination, error) {
	name = Normalize(name)
	if name == "" {
		return Destination{}, errors.New("name: required")
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return Destination{}, fmt.Errorf("name: %s is an address; destinations are named", name)
	}
	d := Destination{Name: name, Treatment: Treatment(treatment)}
	switch d.Treatment {
	case Open:
		a, ok := parseAction(def)
		switch {
		case ok:
			d.Default = a
		case def == "":
			return Destination{}, fmt.Errorf("%s: default: required for an open destination (allow, ask or deny)", name)
		default:
			return Destination{}, fmt.Errorf("%s: default: %q is not allow, ask or deny", name, def)
		}
	case Closed:
		if def != "" {
			return Destination{}, fmt.Errorf("%s: default: only an open destination has one", name)
		}
	default:
		return Destination{}, fmt.Errorf("%s: treatment: %q is neither open nor deny", name, treatment)
	}
	if len(ports) == 0 {
		d.Ports = []uint16{443}
		return d, nil
	}
	var err error
	if d.Ports, err = portList(ports); err != nil {
		return Destination{}, fmt.Errorf("%s: %w", name, err)
	}
	return d, nil
}

func (d *Destination) addRules(rules []rawRule, ops map[string]string) error {
	if d.Treatment != Open && (len(rules) > 0 || len(ops) > 0) {
		return fmt.Errorf("%s: rules and operations: only an open destination has them", d.Name)
	}
	for i, rr := range rules {
		r, err := rr.check()
		if err != nil {
			return fmt.Errorf("%s: rules[%d]: %w", d.Name, i, err)
		}
		d.Rules = append(d.Rules, r)
	}
	if len(ops) > 0 {
		d.Operations = map[string]Action{}
	}
	for name, act := range ops {
		if !operationName.MatchString(name) {
			return fmt.Errorf("%s: operations: %q is not an operation name", d.Name, name)
		}
		a, ok := parseAction(act)
		if !ok {
			return fmt.Errorf("%s: operations: %s: %q is not allow, ask or deny", d.Name, name, act)
		}
		d.Operations[name] = a
	}
	return nil
}

func portList(ports []int) ([]uint16, error) {
	out := make([]uint16, 0, len(ports))
	for _, p := range ports {
		if p < 1 || p > 65535 {
			return nil, fmt.Errorf("ports: %d is not a port", p)
		}
		out = append(out, uint16(p))
	}
	return out, nil
}
