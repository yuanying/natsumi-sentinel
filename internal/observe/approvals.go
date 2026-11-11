package observe

import (
	"context"
	"log/slog"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// approvalsPending reads how many approvals wait for an answer from the
// ledger at each scrape.
type approvalsPending struct {
	desc   *prometheus.Desc
	count  func(context.Context) (int, error)
	logger *slog.Logger
}

// NewApprovalsPending registers sentinel_approvals_pending on reg, read
// with count at each scrape. When count fails the series is left out of
// that scrape, and the rest of the metrics are served as ever.
func NewApprovalsPending(reg prometheus.Registerer, count func(context.Context) (int, error), logger *slog.Logger) {
	if logger == nil {
		logger = slog.Default()
	}
	reg.MustRegister(&approvalsPending{
		desc:   prometheus.NewDesc("sentinel_approvals_pending", "Approvals waiting for the owner's answer, read from the ledger; left out when the ledger cannot be read.", nil, nil),
		count:  count,
		logger: logger,
	})
}

func (a *approvalsPending) Describe(ch chan<- *prometheus.Desc) { ch <- a.desc }

func (a *approvalsPending) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	n, err := a.count(ctx)
	if err != nil {
		a.logger.Error("the approvals waiting could not be counted from the ledger", "error", err)
		return
	}
	ch <- prometheus.MustNewConstMetric(a.desc, prometheus.GaugeValue, float64(n))
}
