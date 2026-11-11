// Command sentinel is the gate in front of the workspace's way out. It takes
// the workspace's outgoing traffic, decides on each request and records
// what goes out (docs/adr/0001, 0002, 0006).
//
// Requests on open destinations are sent upstream by authd, through its
// socket (docs/adr/0003). The gate connects to it on first use: while authd
// cannot be reached, every request on an open destination is refused
// (docs/adr/0001).
//
// stdout carries the copy of the audit records, one JSON object per line.
// What the gate itself has to say goes to stderr.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/yuanying/natsumi-sentinel/internal/audit"
	"github.com/yuanying/natsumi-sentinel/internal/authdclient"
	"github.com/yuanying/natsumi-sentinel/internal/buildinfo"
	"github.com/yuanying/natsumi-sentinel/internal/certs"
	"github.com/yuanying/natsumi-sentinel/internal/decide"
	"github.com/yuanying/natsumi-sentinel/internal/dnsgate"
	"github.com/yuanying/natsumi-sentinel/internal/gate"
	"github.com/yuanying/natsumi-sentinel/internal/origdst"
	"github.com/yuanying/natsumi-sentinel/internal/routes"
)

const program = "sentinel"

// version is set by the build (-X main.version).
var version = "dev"

// newUpstream gives the http.RoundTripper that sends requests on open
// destinations through authd's socket. Tests replace it.
var newUpstream = func(socket string) http.RoundTripper { return authdclient.NewTransport(socket) }

// onListen is told each address the gate listens on. Tests replace it.
var onListen = func(source, what string, addr net.Addr) {}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

// source is one listener pair: where the connections and the name
// resolution redirected from one place arrive (docs/adr/0002).
type source struct {
	name, proxy, dns string
}

type sourceFlag []source

func (s *sourceFlag) String() string { return "" }

func (s *sourceFlag) Set(v string) error {
	var src source
	for _, kv := range strings.Split(v, ",") {
		k, val, ok := strings.Cut(kv, "=")
		if !ok || val == "" {
			return fmt.Errorf("%q is not key=value", kv)
		}
		switch k {
		case "name":
			src.name = val
		case "proxy":
			src.proxy = val
		case "dns":
			src.dns = val
		default:
			return fmt.Errorf("unknown key %q", k)
		}
	}
	if src.name == "" || src.proxy == "" || src.dns == "" {
		return errors.New("name, proxy and dns are all required")
	}
	for _, o := range *s {
		if o.name == src.name {
			return fmt.Errorf("source %q is given twice", src.name)
		}
	}
	*s = append(*s, src)
	return nil
}

type options struct {
	config, caCert, caKey, db string
	authdSocket               string
	sources                   sourceFlag
	gateName, gateAddress     string
	reload                    time.Duration
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet(program, flag.ContinueOnError)
	fs.SetOutput(stderr)
	showVersion := fs.Bool("version", false, "print the version and exit")
	check := fs.Bool("check", false, "check the routing table in -config and exit")
	var o options
	fs.StringVar(&o.config, "config", "", "the directory of the routing table (docs/routes.md)")
	fs.StringVar(&o.caCert, "ca-cert", "", "the gate's CA certificate, PEM")
	fs.StringVar(&o.caKey, "ca-key", "", "the gate's CA private key, PEM")
	fs.StringVar(&o.db, "db", "", "the SQLite file of the audit log; its directory must exist")
	fs.StringVar(&o.authdSocket, "authd-socket", "", "authd's Unix socket, where requests on open destinations are handed on")
	fs.Var(&o.sources, "source", "a listener pair, name=NAME,proxy=ADDR,dns=ADDR; repeat for each place redirected from")
	fs.StringVar(&o.gateName, "gate-name", "", "the gate's own fixed name, answered in name resolution")
	fs.StringVar(&o.gateAddress, "gate-address", "", "the IPv4 address -gate-name is answered with")
	fs.DurationVar(&o.reload, "reload-interval", 10*time.Second, "how often the routing table is checked for changes")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *showVersion {
		if err := buildinfo.WriteVersion(stdout, program, version); err != nil {
			return 1
		}
		return 0
	}
	if o.config == "" {
		_, _ = fmt.Fprintln(stderr, "sentinel: -config is required")
		return 2
	}
	if *check {
		if _, err := routes.Load(o.config); err != nil {
			_, _ = fmt.Fprintf(stderr, "sentinel: the routing table cannot be used: %v\n", err)
			return 1
		}
		_, _ = fmt.Fprintf(stdout, "the routing table in %s can be used\n", o.config)
		return 0
	}
	fixed, err := o.validate()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sentinel: %v\n", err)
		return 2
	}

	logger := slog.New(slog.NewJSONHandler(stderr, nil))
	if err := start(ctx, o, fixed, stdout, logger); err != nil {
		logger.Error("the gate does not start", "error", err)
		return 1
	}
	return 0
}

func (o *options) validate() (map[string]netip.Addr, error) {
	switch {
	case o.caCert == "" || o.caKey == "":
		return nil, errors.New("-ca-cert and -ca-key are required")
	case o.db == "":
		return nil, errors.New("-db is required")
	case o.authdSocket == "":
		return nil, errors.New("-authd-socket is required")
	case len(o.sources) == 0:
		return nil, errors.New("at least one -source is required")
	case o.reload <= 0:
		return nil, errors.New("-reload-interval must be positive")
	}
	if (o.gateName == "") != (o.gateAddress == "") {
		return nil, errors.New("-gate-name and -gate-address go together")
	}
	if o.gateName == "" {
		return nil, nil
	}
	addr, err := netip.ParseAddr(o.gateAddress)
	if err != nil || !addr.Is4() {
		return nil, fmt.Errorf("-gate-address %q is not an IPv4 address", o.gateAddress)
	}
	return map[string]netip.Addr{o.gateName: addr}, nil
}

// start sets the gate up, failing closed on anything it cannot have, and
// serves until ctx is done.
func start(ctx context.Context, o options, fixed map[string]netip.Addr, stdout io.Writer, logger *slog.Logger) error {
	watcher, err := routes.NewWatcher(o.config)
	if err != nil {
		return fmt.Errorf("the routing table: %w", err)
	}
	minter, err := certs.Load(o.caCert, o.caKey)
	if err != nil {
		return err
	}
	log, err := audit.Open(o.db, stdout)
	if err != nil {
		return err
	}
	defer func() { _ = log.Close() }()
	upstream := newUpstream(o.authdSocket)

	var (
		closers []func() error
		wg      sync.WaitGroup
	)
	defer func() {
		for _, c := range closers {
			_ = c()
		}
		wg.Wait()
	}()
	for _, src := range o.sources {
		g := gate.New(gate.Config{
			Source:      src.name,
			Routes:      watcher.Current,
			Decider:     decide.Table{},
			Minter:      minter,
			Log:         log,
			Upstream:    upstream,
			OriginalDst: origdst.Lookup,
			Logger:      logger.With("source", src.name),
		})
		closers = append(closers, g.Close)
		ln, err := net.Listen("tcp", src.proxy)
		if err != nil {
			return fmt.Errorf("source %s: %w", src.name, err)
		}
		closers = append(closers, ln.Close)
		onListen(src.name, "proxy", ln.Addr())

		dns := dnsgate.New(dnsgate.Config{
			Source:   src.name,
			Routes:   watcher.Current,
			Resolver: net.DefaultResolver,
			Fixed:    fixed,
			Log:      log,
			Logger:   logger.With("source", src.name),
		})
		pc, err := net.ListenPacket("udp", src.dns)
		if err != nil {
			return fmt.Errorf("source %s: %w", src.name, err)
		}
		closers = append(closers, pc.Close)
		onListen(src.name, "dns-udp", pc.LocalAddr())
		tl, err := net.Listen("tcp", src.dns)
		if err != nil {
			return fmt.Errorf("source %s: %w", src.name, err)
		}
		closers = append(closers, tl.Close)
		onListen(src.name, "dns-tcp", tl.Addr())

		wg.Add(3)
		go func() { defer wg.Done(); logIf(logger, g.Serve(ln)) }()
		go func() { defer wg.Done(); logIf(logger, dns.ServeUDP(pc)) }()
		go func() { defer wg.Done(); logIf(logger, dns.ServeTCP(tl)) }()
	}

	wg.Add(2)
	go func() {
		defer wg.Done()
		watcher.Run(ctx, o.reload, func(err error) { recordReload(log, logger, err) })
	}()
	go func() {
		defer wg.Done()
		audit.RunPruner(ctx, log, 24*time.Hour,
			func() time.Duration { return watcher.Current().Audit().Retention },
			func(n int64, err error) {
				if err != nil {
					logger.Error("old audit records could not be deleted", "error", err)
					return
				}
				logger.Info("old audit records deleted", "count", n)
			})
	}()
	logger.Info("the gate is serving", "version", version)
	<-ctx.Done()
	logger.Info("the gate is stopping")
	return nil
}

// recordReload records the routing table being read again, or failing to
// be, so that a table that did not take is in the record (docs/adr/0004).
func recordReload(log *audit.Log, logger *slog.Logger, err error) {
	rec := &audit.Record{Time: time.Now(), Kind: audit.KindConfig}
	if err != nil {
		rec.Verdict = audit.Deny
		rec.Reason = "the routing table was not taken; the previous one stays in use"
		rec.Error = err.Error()
		logger.Error("the routing table was not taken; the previous one stays in use", "error", err)
	} else {
		rec.Verdict = audit.Allow
		rec.Reason = "the routing table was read again"
		logger.Info("the routing table was read again")
	}
	if werr := log.Write(context.Background(), rec); werr != nil {
		logger.Error("reading the routing table again could not be recorded", "error", werr)
	}
}

func logIf(logger *slog.Logger, err error) {
	if err != nil {
		logger.Error("a listener stopped", "error", err)
	}
}
