// Package metrics is what sentinel and authd share to put out their
// Prometheus metrics (docs/adr/0006, docs/metrics.md).
//
// Nothing that goes into a metric may be a key, a token or a surrogate, and
// no label may take a value the workspace can choose freely (a path, a
// query, a name not in the routing table): each label has a small, fixed
// set of values, so that the number of series stays bounded.
package metrics

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Path is where the metrics page is served.
const Path = "/metrics"

// NewRegistry returns a registry holding the Go runtime's and the process's
// metrics, and <program>_build_info, which is always 1 and carries the
// version: a series that is there for as long as the program is up, for
// noticing from outside that it stopped.
func NewRegistry(program, version string) *prometheus.Registry {
	reg := prometheus.NewRegistry()
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	info := prometheus.NewGauge(prometheus.GaugeOpts{
		Name:        program + "_build_info",
		Help:        "Always 1; the version of the running build is its label.",
		ConstLabels: prometheus.Labels{"version": version},
	})
	info.Set(1)
	reg.MustRegister(info)
	return reg
}

// Handler serves the metrics page at Path and nothing else.
func Handler(reg *prometheus.Registry) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET "+Path, promhttp.HandlerFor(reg, promhttp.HandlerOpts{Registry: reg}))
	return mux
}

// Serve serves the metrics page on ln until ctx is done. It returns nil once
// it has stopped because ctx was done, and the error otherwise.
func Serve(ctx context.Context, ln net.Listener, reg *prometheus.Registry) error {
	srv := &http.Server{Handler: Handler(reg), ReadHeaderTimeout: 10 * time.Second}
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ln) }()
	select {
	case err := <-served:
		return err
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdown); err != nil {
		_ = srv.Close()
	}
	// Serve gives http.ErrServerClosed once it has been shut down.
	if err := <-served; !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
