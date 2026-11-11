// Command authd is the key keeper. It holds the real keys, and sends every
// request the gate has decided on to the upstream, swapping registered
// surrogates for their real keys on the way (docs/adr/0001, 0003).
//
// authd listens on a Unix socket and takes connections only from the gate's
// UID. It does not start on a registration it cannot use.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/yuanying/natsumi-sentinel/internal/authd"
	"github.com/yuanying/natsumi-sentinel/internal/buildinfo"
	"github.com/yuanying/natsumi-sentinel/internal/peercred"
)

const program = "authd"

// version is set by the build (-X main.version).
var version = "dev"

// shutdownGrace is how long requests in flight are given to finish once
// authd is told to stop. Watches and log streams do not finish by
// themselves, so after this they are cut.
const shutdownGrace = 10 * time.Second

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet(program, flag.ContinueOnError)
	fs.SetOutput(stderr)
	showVersion := fs.Bool("version", false, "print the version and exit")
	configPath := fs.String("config", "", "the registration of surrogates and upstreams (required)")
	socketPath := fs.String("socket", "", "the Unix socket to listen on (required)")
	peerUID := fs.Int("peer-uid", -1, "the gate's UID, the only one whose connections are taken (required)")
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
	switch {
	case *configPath == "":
		return usage(stderr, "--config is required")
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
	handler, err := authd.NewHandler(cfg, authd.Options{Logger: log})
	if err != nil {
		log.Error("cannot set up the handler", "error", err.Error())
		return 1
	}
	l, err := peercred.Listen(*socketPath, *peerUID, func(uid int) {
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

func usage(stderr io.Writer, msg string) int {
	_, _ = fmt.Fprintf(stderr, "%s: %s\n", program, msg)
	return 2
}
