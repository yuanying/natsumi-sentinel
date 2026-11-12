// Command authd is the key keeper. It holds the real keys, and sends every
// request the gate has decided on to the upstream, swapping registered
// surrogates for their real keys on the way (docs/adr/0001, 0003).
//
// authd listens on a Unix socket and takes connections only from the gate's
// UID. It does not start on a registration it cannot use, but a key file
// that cannot be read only refuses the requests that use it. --check checks
// the registration and exits.
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
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/yuanying/natsumi-sentinel/internal/authd"
	"github.com/yuanying/natsumi-sentinel/internal/buildinfo"
	"github.com/yuanying/natsumi-sentinel/internal/metrics"
	"github.com/yuanying/natsumi-sentinel/internal/peercred"
)

const program = "authd"

// version is set by the build (-X main.version).
var version = "dev"

// shutdownGrace is how long requests in flight are given to finish once
// authd is told to stop. Watches and log streams do not finish by
// themselves, so after this they are cut.
const shutdownGrace = 10 * time.Second

// onMetricsListen is told the address the metrics are served on. Tests
// replace it.
var onMetricsListen = func(net.Addr) {}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet(program, flag.ContinueOnError)
	fs.SetOutput(stderr)
	showVersion := fs.Bool("version", false, "print the version and exit")
	check := fs.Bool("check", false, "check the registration in --config and its CA files, and exit; a key file that cannot be read is told but is not an error")
	configPath := fs.String("config", "", "the registration of surrogates and upstreams (required)")
	socketPath := fs.String("socket", "", "the Unix socket to listen on (required)")
	peerUID := fs.Int("peer-uid", -1, "the gate's UID, the only one whose connections are taken (required)")
	metricsAddr := fs.String("metrics-listen", "", "the TCP address to serve the Prometheus metrics on, at /metrics; empty serves none")
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
	if *configPath == "" {
		return usage(stderr, "--config is required")
	}
	if *check {
		return checkConfig(*configPath, stdout, stderr)
	}
	switch {
	case *socketPath == "":
		return usage(stderr, "--socket is required")
	case *peerUID < 0:
		return usage(stderr, "--peer-uid is required")
	}

	log := slog.New(slog.NewJSONHandler(stderr, nil)).With("program", program)
	cfg, err := authd.LoadConfig(*configPath)
	if err != nil {
		log.Error("the registration cannot be used", "error", err.Error())
		return 1
	}
	m := newAuthdMetrics(cfg.Credentials())
	// A key that cannot be read does not stop the start: the requests that
	// use it are refused, as they are when it cannot be read later.
	for _, k := range cfg.UnreadableKeys() {
		log.Warn("a real key cannot be read at the start; the requests that use it are refused until it can be",
			"credential", k.Credential, "key_file", k.KeyFile, "error", k.Problem)
		m.onKeyUnreadable(k.Credential)
	}
	handler, err := authd.NewHandler(cfg, authd.Options{
		Logger:          log,
		OnError:         m.onError,
		OnKeyUnreadable: m.onKeyUnreadable,
	})
	if err != nil {
		log.Error("cannot set up the handler", "error", err.Error())
		return 1
	}
	// metricsFailed stays nil, and so never ready, without metrics.
	var metricsFailed chan error
	if *metricsAddr != "" {
		ml, err := net.Listen("tcp", *metricsAddr)
		if err != nil {
			log.Error("cannot listen for the metrics", "address", *metricsAddr, "error", err.Error())
			return 1
		}
		onMetricsListen(ml.Addr())
		metricsCtx, stopMetrics := context.WithCancel(ctx)
		metricsFailed = make(chan error, 1)
		stopped := make(chan struct{})
		go func() {
			defer close(stopped)
			if err := metrics.Serve(metricsCtx, ml, m.reg); err != nil {
				metricsFailed <- err
			}
		}()
		defer func() { stopMetrics(); <-stopped }()
	}
	l, err := peercred.Listen(*socketPath, *peerUID, func(uid int) {
		m.refusedPeers.Inc()
		log.Warn("refused a connection from another UID", "uid", uid)
	})
	if err != nil {
		log.Error("cannot listen", "socket", *socketPath, "error", err.Error())
		return 1
	}

	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	served := make(chan error, 1)
	go func() { served <- srv.Serve(l) }()
	log.Info("listening", "socket", *socketPath, "peer_uid", *peerUID, "version", version)

	select {
	case err := <-served:
		log.Error("serving stopped", "error", err.Error())
		return 1
	case err := <-metricsFailed:
		log.Error("serving the metrics stopped", "error", err.Error())
		_ = srv.Close()
		return 1
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		_ = srv.Close()
	}
	log.Info("stopped")
	return 0
}

// checkConfig loads the registration as the start does, and says whether it
// can be used. A key file that cannot be read is told, but is not an error:
// the start does not stop on one, and a check is run where the keys are
// not (a CI, say).
func checkConfig(path string, stdout, stderr io.Writer) int {
	cfg, err := authd.LoadConfig(path)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "%s: the registration cannot be used: %v\n", program, err)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "the registration in %s can be used\n", path)
	for _, k := range cfg.UnreadableKeys() {
		_, _ = fmt.Fprintf(stdout, "credentials[%d]: key_file %s: %s; the requests that use it would be refused\n", k.Credential, k.KeyFile, k.Problem)
	}
	return 0
}

func usage(stderr io.Writer, msg string) int {
	_, _ = fmt.Fprintf(stderr, "%s: %s\n", program, msg)
	return 2
}
