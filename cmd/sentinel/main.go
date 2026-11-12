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
	// The image may have no time zones of its own for -summary-timezone.
	_ "time/tzdata"

	"github.com/yuanying/natsumi-sentinel/internal/approvals"
	"github.com/yuanying/natsumi-sentinel/internal/audit"
	"github.com/yuanying/natsumi-sentinel/internal/authdclient"
	"github.com/yuanying/natsumi-sentinel/internal/buildinfo"
	"github.com/yuanying/natsumi-sentinel/internal/certs"
	"github.com/yuanying/natsumi-sentinel/internal/decide"
	"github.com/yuanying/natsumi-sentinel/internal/dnsgate"
	"github.com/yuanying/natsumi-sentinel/internal/gate"
	"github.com/yuanying/natsumi-sentinel/internal/github"
	"github.com/yuanying/natsumi-sentinel/internal/ledger"
	"github.com/yuanying/natsumi-sentinel/internal/metrics"
	"github.com/yuanying/natsumi-sentinel/internal/notice"
	"github.com/yuanying/natsumi-sentinel/internal/observe"
	"github.com/yuanying/natsumi-sentinel/internal/origdst"
	"github.com/yuanying/natsumi-sentinel/internal/peercred"
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
// resolution redirected from one place arrive (docs/adr/0002). proxy6 and
// dns6 are where its IPv6 arrives, when that is redirected too; then the
// open names are answered in AAAA (docs/redirect.md).
type source struct {
	name, proxy, dns string
	proxy6, dns6     string
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
		case "proxy6":
			src.proxy6 = val
		case "dns6":
			src.dns6 = val
		default:
			return fmt.Errorf("unknown key %q", k)
		}
	}
	if src.name == "" || src.proxy == "" || src.dns == "" {
		return errors.New("name, proxy and dns are all required")
	}
	if (src.proxy6 == "") != (src.dns6 == "") {
		return errors.New("proxy6 and dns6 go together")
	}
	for k, v := range map[string]string{"proxy6": src.proxy6, "dns6": src.dns6} {
		if v == "" {
			continue
		}
		ap, err := netip.ParseAddrPort(v)
		if err != nil || !ap.Addr().Is6() || ap.Addr().Is4In6() {
			return fmt.Errorf("%s %q is not an IPv6 address and port, such as [::1]:15002", k, v)
		}
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
	authdSocket, ledger       string
	approvalsSocket           string
	approvalsUID              int
	sources                   sourceFlag
	gateName, gateAddress     string
	searchSuffixes            listFlag
	reload                    time.Duration
	metrics                   string
	notices                   noticeOptions
}

// noticeOptions are the settings of the notices (docs/notices.md). None of
// them stops the gate: what cannot be used is logged, and the notices go
// on as well as they can without it.
type noticeOptions struct {
	alertmanager    string
	surrogate       string
	labels          listFlag
	summaryAt, zone string
	queue           int
}

type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, ",") }

func (l *listFlag) Set(v string) error {
	*l = append(*l, v)
	return nil
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
	fs.StringVar(&o.ledger, "ledger", "", "the SQLite file of the ledger of approvals and grants; its directory must exist")
	fs.StringVar(&o.approvalsSocket, "approvals-socket", "", "the Unix socket the owner's door (natsumi's server) is served on")
	fs.IntVar(&o.approvalsUID, "approvals-peer-uid", -1, "the server's UID, the only one taken on -approvals-socket")
	fs.Var(&o.sources, "source", "a listener pair, name=NAME,proxy=ADDR,dns=ADDR, with proxy6=ADDR,dns6=ADDR when IPv6 is redirected too; repeat for each place redirected from")
	fs.StringVar(&o.gateName, "gate-name", "", "the gate's own fixed name, answered in name resolution; the workspace's door is http://NAME/")
	fs.StringVar(&o.gateAddress, "gate-address", "", "the IPv4 address -gate-name is answered with")
	fs.Var(&o.searchSuffixes, "dns-search-suffix", "a search suffix of the workspace's resolver, such as svc.cluster.local; a refused name in the table with it added is recorded but not noticed; repeat for each")
	fs.DurationVar(&o.reload, "reload-interval", 10*time.Second, "how often the routing table is checked for changes")
	fs.StringVar(&o.metrics, "metrics-listen", "", "the TCP address to serve the Prometheus metrics on, at /metrics; empty serves none")
	fs.StringVar(&o.notices.alertmanager, "alertmanager-url", "", "Alertmanager's https base URL, reached through authd, to send the notices to; empty only logs them")
	fs.StringVar(&o.notices.surrogate, "alertmanager-surrogate", "", "a surrogate put on the notices as Authorization: Bearer, for authd to swap for the key of an Alertmanager behind a door that wants one; empty puts none")
	fs.Var(&o.notices.labels, "alert-label", "a label, name=value, put on every alert sent; repeat for each")
	fs.StringVar(&o.notices.summaryAt, "summary-at", "00:00", "the time of day, HH:MM, of the daily summary, which covers the day up to it")
	fs.StringVar(&o.notices.zone, "summary-timezone", "UTC", "the time zone of -summary-at, as an IANA name")
	fs.IntVar(&o.notices.queue, "notice-queue", 1000, "how many notices may wait to be sent again before the oldest are dropped")
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
	case o.ledger == "":
		return nil, errors.New("-ledger is required")
	case o.approvalsSocket == "":
		return nil, errors.New("-approvals-socket is required")
	case o.approvalsUID < 0:
		return nil, errors.New("-approvals-peer-uid is required")
	case len(o.sources) == 0:
		return nil, errors.New("at least one -source is required")
	case o.reload <= 0:
		return nil, errors.New("-reload-interval must be positive")
	}
	for _, sfx := range o.searchSuffixes {
		if !validSuffix(sfx) {
			return nil, fmt.Errorf("-dns-search-suffix %q is not a name", sfx)
		}
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

// validSuffix reports whether s is a name to take as a search suffix: dot
// separated labels, none empty, with no white space. A leading or a
// trailing dot is let be.
func validSuffix(s string) bool {
	s = strings.TrimSuffix(strings.TrimPrefix(s, "."), ".")
	if s == "" || strings.ContainsAny(s, " \t/:@") {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" {
			return false
		}
	}
	return true
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
	db, err := audit.Open(o.db, stdout)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	book, err := ledger.Open(o.ledger, nil)
	if err != nil {
		return err
	}
	defer func() { _ = book.Close() }()
	upstream := newUpstream(o.authdSocket)

	reg := metrics.NewRegistry(program, version)
	var fixedNames []string
	for name := range fixed {
		fixedNames = append(fixedNames, name)
	}
	gm := observe.NewGateMetrics(reg, watcher.Current, fixedNames)
	observe.NewApprovalsPending(reg, book.CountOpen, logger)
	// Everything the gate records goes through log, so that the metrics
	// and the notices see it. pairs is set below, before anything is
	// recorded.
	var pairs *notice.Watcher
	log := observe.NewRecorder(db, gm.Observe, func(ev observe.Event) { pairs.Observe(ev) })
	// The GitHub connector asks its questions through authd too, and
	// records them as the gate's own (docs/adr/0005).
	decider := decide.Table{Ledger: book, GitHub: &github.Connector{Transport: upstream, Log: log, Logger: logger.With("part", "github")}}
	outbox, summary := setUpNotices(o.notices, notice.OutboxConfig{
		Logger:     logger.With("part", "notices"),
		Registerer: reg,
	}, upstream, log, db, func() int64 { return watcher.Current().Audit().BodyLimit })
	pairs = notice.NewWatcher(notice.WatcherConfig{Log: db, Outbox: outbox, Logger: logger, Registerer: reg})
	// The doors write through log too, so the answers are counted and
	// watched like every other record, and read straight from db.
	records := approvalRecords{Log: log, db: db}

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
	ol, err := peercred.Listen(o.approvalsSocket, o.approvalsUID, func(uid int) {
		logger.Warn("refused a connection to the approvals socket from another UID", "uid", uid)
	})
	if err != nil {
		return fmt.Errorf("the approvals socket: %w", err)
	}
	owner := &http.Server{
		Handler: approvals.Owner(approvals.OwnerConfig{
			Ledger: book, Log: records,
			Answered: func(a *ledger.Approval) { outbox.Put(notice.Answered(a)) },
			Revoked:  func(g *ledger.Grant, at time.Time) { outbox.Put(notice.Revoked(g, at)) },
		}),
		ReadHeaderTimeout: 10 * time.Second,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}
	closers = append(closers, owner.Close)
	onListen("", "approvals", ol.Addr())
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := owner.Serve(ol); !errors.Is(err, http.ErrServerClosed) {
			logIf(logger, err)
		}
	}()

	if o.metrics != "" {
		ml, err := net.Listen("tcp", o.metrics)
		if err != nil {
			return fmt.Errorf("the metrics: %w", err)
		}
		onListen("", "metrics", ml.Addr())
		// Stopped with the rest, also when the start fails further on.
		metricsCtx, stopMetrics := context.WithCancel(ctx)
		closers = append(closers, func() error { stopMetrics(); return nil })
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := metrics.Serve(metricsCtx, ml, reg); err != nil {
				logger.Error("serving the metrics stopped", "error", err)
			}
		}()
	}
	for _, src := range o.sources {
		cfg := gate.Config{
			Source:      src.name,
			Routes:      watcher.Current,
			Decider:     decider,
			Minter:      minter,
			Log:         log,
			Upstream:    gm.Upstream(upstream),
			OriginalDst: origdst.Lookup,
			Logger:      logger.With("source", src.name),
		}
		for name, addr := range fixed {
			cfg.AgentAddr = netip.AddrPortFrom(addr, 80)
			cfg.StatusURL = "http://" + name + "/v1/status"
			cfg.Agent = approvals.Agent(approvals.AgentConfig{Source: src.name, Ledger: book, Log: records, Routes: watcher.Current})
		}
		g := gate.New(cfg)
		closers = append(closers, g.Close)
		ln, err := net.Listen("tcp", src.proxy)
		if err != nil {
			return fmt.Errorf("source %s: %w", src.name, err)
		}
		closers = append(closers, ln.Close)
		onListen(src.name, "proxy", ln.Addr())
		if src.proxy6 != "" {
			ln6, err := net.Listen("tcp6", src.proxy6)
			if err != nil {
				return fmt.Errorf("source %s: %w", src.name, err)
			}
			closers = append(closers, ln6.Close)
			onListen(src.name, "proxy6", ln6.Addr())
			wg.Add(1)
			go func() { defer wg.Done(); logIf(logger, g.Serve(ln6)) }()
		}

		dns := dnsgate.New(dnsgate.Config{
			Source:   src.name,
			Routes:   watcher.Current,
			Resolver: net.DefaultResolver,
			Fixed:    fixed,
			Log:      log,
			// The search suffixes are the resolver's, the same for
			// every source of one Pod.
			SearchSuffixes: o.searchSuffixes,
			IPv6:           src.proxy6 != "",
			Logger:         logger.With("source", src.name),
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

		if src.dns6 != "" {
			pc6, err := net.ListenPacket("udp6", src.dns6)
			if err != nil {
				return fmt.Errorf("source %s: %w", src.name, err)
			}
			closers = append(closers, pc6.Close)
			onListen(src.name, "dns6-udp", pc6.LocalAddr())
			tl6, err := net.Listen("tcp6", src.dns6)
			if err != nil {
				return fmt.Errorf("source %s: %w", src.name, err)
			}
			closers = append(closers, tl6.Close)
			onListen(src.name, "dns6-tcp", tl6.Addr())
			wg.Add(2)
			go func() { defer wg.Done(); logIf(logger, dns.ServeUDP(pc6)) }()
			go func() { defer wg.Done(); logIf(logger, dns.ServeTCP(tl6)) }()
		}

		wg.Add(3)
		go func() { defer wg.Done(); logIf(logger, g.Serve(ln)) }()
		go func() { defer wg.Done(); logIf(logger, dns.ServeUDP(pc)) }()
		go func() { defer wg.Done(); logIf(logger, dns.ServeTCP(tl)) }()
	}

	wg.Add(6)
	go func() {
		defer wg.Done()
		book.RunSweeper(ctx, time.Minute, func(err error) {
			logger.Error("the ledger could not be swept of what has ended", "error", err)
		})
	}()
	go func() { defer wg.Done(); outbox.Run(ctx) }()
	go func() { defer wg.Done(); pairs.Run(ctx) }()
	go func() { defer wg.Done(); summary.Run(ctx) }()
	go func() {
		defer wg.Done()
		watcher.Run(ctx, o.reload, func(err error) { recordReload(log, logger, err) })
	}()
	go func() {
		defer wg.Done()
		audit.RunPruner(ctx, db, 24*time.Hour,
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

// setUpNotices makes the outbox of the notices, sending to Alertmanager
// through the same sender as the workspace's requests when it is set, and
// the daily summary. What of the settings cannot be used is logged and left
// out: the notices are never a reason not to start.
func setUpNotices(o noticeOptions, cfg notice.OutboxConfig, upstream http.RoundTripper, log observe.Log, db *audit.Log, bodyLimit func() int64) (*notice.Outbox, *notice.Summarizer) {
	logger := cfg.Logger
	labels := map[string]string{}
	for _, l := range o.labels {
		k, v, ok := strings.Cut(l, "=")
		if !ok || k == "" {
			logger.Error("an -alert-label is not name=value, so it is not used", "label", l)
			continue
		}
		labels[k] = v
	}
	if o.alertmanager != "" {
		am, err := notice.NewAlertmanager(notice.AlertmanagerConfig{
			URL:       o.alertmanager,
			Surrogate: o.surrogate,
			Transport: upstream,
			Log:       log,
			Labels:    labels,
			BodyLimit: bodyLimit,
		})
		if err != nil {
			// Neither the URL nor the surrogate is logged: the URL is
			// not to carry a secret, but a mistaken one could, and the
			// surrogate has no need to be told.
			logger.Error("-alertmanager-url or -alertmanager-surrogate cannot be used, so the notices are only logged", "error", err)
		} else {
			cfg.Sender = am
		}
	} else {
		logger.Warn("no -alertmanager-url: the notices are only logged")
		if o.surrogate != "" {
			logger.Error("-alertmanager-surrogate is given without -alertmanager-url, so it is not used")
		}
	}
	cfg.Max = o.queue

	zone, err := time.LoadLocation(o.zone)
	if err != nil {
		logger.Error("-summary-timezone cannot be used; the summary is in UTC", "zone", o.zone, "error", err)
		zone = time.UTC
	}
	outbox := notice.NewOutbox(cfg)
	sc := notice.SummaryConfig{Log: db, Outbox: outbox, At: o.summaryAt, Location: zone, Logger: logger, Registerer: cfg.Registerer}
	summary, err := notice.NewSummarizer(sc)
	if err != nil {
		logger.Error("-summary-at cannot be used; the summary is at 00:00", "error", err)
		sc.At = "00:00"
		summary, _ = notice.NewSummarizer(sc)
	}
	return outbox, summary
}

// approvalRecords is the audit log as the approvals doors use it: written
// through the recorder the metrics and notices watch, read from the file.
type approvalRecords struct {
	observe.Log
	db *audit.Log
}

func (r approvalRecords) List(ctx context.Context, q audit.Query) ([]*audit.Record, error) {
	return r.db.List(ctx, q)
}

func (r approvalRecords) Get(ctx context.Context, id int64) (*audit.Record, error) {
	return r.db.Get(ctx, id)
}

// recordReload records the routing table being read again, or failing to
// be, so that a table that did not take is in the record (docs/adr/0004).
func recordReload(log observe.Log, logger *slog.Logger, err error) {
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
