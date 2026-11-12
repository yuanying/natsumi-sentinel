package notice

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/yuanying/natsumi-sentinel/internal/audit"
)

// Recorder is the audit log as the sender records its own requests.
type Recorder interface {
	Begin(ctx context.Context, rec *audit.Record) error
	Finish(ctx context.Context, rec *audit.Record) error
}

// AlertmanagerConfig is what an Alertmanager sender needs.
type AlertmanagerConfig struct {
	// URL is Alertmanager's base, https. The alerts are posted to
	// /api/v2/alerts under it.
	URL string
	// Surrogate, when set, is put on every request as
	// "Authorization: Bearer <surrogate>", for authd to swap for the key
	// of an Alertmanager behind a door that wants one (docs/adr/0003). It
	// is not a secret, but it is not told in records, logs or errors
	// either: there is no need to.
	Surrogate string
	// Transport sends the requests. In the gate it is the sender to
	// authd, the same one the workspace's requests go through.
	Transport http.RoundTripper
	// Log records each request sent, as one of the gate's own.
	Log Recorder
	// Labels are put on every alert, besides the notice's own.
	Labels map[string]string
	// BodyLimit is how much of what is sent the record keeps. Nil keeps
	// all of it.
	BodyLimit func() int64
	Now       func() time.Time
}

// Alertmanager posts notices to Alertmanager's v2 API as alerts.
type Alertmanager struct {
	cfg    AlertmanagerConfig
	url    *url.URL
	client *http.Client
}

// alertLife is how long after it is sent an alert ends. A notice is told
// once; it has no state to resolve. The end is set from the time it is
// sent, so that one sent late is still told.
const alertLife = time.Hour

// NewAlertmanager makes the sender, checking the URL.
func NewAlertmanager(cfg AlertmanagerConfig) (*Alertmanager, error) {
	u, err := url.Parse(cfg.URL)
	switch {
	case err != nil:
		return nil, fmt.Errorf("the Alertmanager URL: %w", err)
	case u.Scheme != "https" || u.Host == "" || u.Hostname() == "":
		return nil, errors.New("the Alertmanager URL must be https://name[:port][/path]")
	case u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.HasSuffix(cfg.URL, "#"):
		return nil, errors.New("the Alertmanager URL may not carry a user, a query or a fragment")
	}
	if cfg.Surrogate != "" && !bearerValue(cfg.Surrogate) {
		return nil, errors.New("the Alertmanager surrogate must be visible ASCII characters with no spaces")
	}
	u.Path = strings.TrimSuffix(u.Path, "/") + "/api/v2/alerts"
	u.RawPath = ""
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Alertmanager{
		cfg: cfg,
		url: u,
		client: &http.Client{
			Transport: cfg.Transport,
			Timeout:   30 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

type alert struct {
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`
	StartsAt    time.Time         `json:"startsAt"`
	EndsAt      time.Time         `json:"endsAt"`
}

var alertNames = map[string]string{
	TypeFirstSeen:    "SentinelFirstSeen",
	TypeDailySummary: "SentinelDailySummary",
	TypeAnswer:       "SentinelAnswer",
}

// Send implements Sender. Nothing is sent that could not be recorded.
func (a *Alertmanager) Send(ctx context.Context, notices []Notice) error {
	now := a.cfg.Now()
	alerts := make([]alert, 0, len(notices))
	for _, n := range notices {
		labels := map[string]string{}
		for k, v := range a.cfg.Labels {
			labels[k] = v
		}
		for k, v := range n.Labels {
			labels[k] = v
		}
		labels["alertname"] = alertNames[n.Type]
		labels["severity"] = "info"
		annotations := map[string]string{"summary": n.Summary}
		if n.Description != "" {
			annotations["description"] = n.Description
		}
		alerts = append(alerts, alert{Labels: labels, Annotations: annotations, StartsAt: n.At.UTC(), EndsAt: now.Add(alertLife).UTC()})
	}
	body, err := json.Marshal(alerts)
	if err != nil {
		return err
	}

	rec := &audit.Record{
		Time:    now,
		Kind:    audit.KindGate,
		Name:    a.url.Hostname(),
		Method:  http.MethodPost,
		Path:    a.url.Path,
		Verdict: audit.Allow,
		Reason:  "the gate's own notices, to Alertmanager",
		Request: a.kept(body),
	}
	if err := a.cfg.Log.Begin(ctx, rec); err != nil {
		return fmt.Errorf("the notices could not be recorded, so they were not sent: %w", err)
	}
	defer func() {
		rec.Duration = a.cfg.Now().Sub(now)
		_ = a.cfg.Log.Finish(context.Background(), rec)
	}()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.url.String(), bytes.NewReader(body))
	if err != nil {
		rec.Error = err.Error()
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if a.cfg.Surrogate != "" {
		req.Header.Set("Authorization", "Bearer "+a.cfg.Surrogate)
	}
	resp, err := a.client.Do(req)
	if err != nil {
		rec.Error = err.Error()
		return fmt.Errorf("post to Alertmanager: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	n, _ := io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	rec.Status = resp.StatusCode
	rec.ResponseBytes = n
	if resp.StatusCode/100 != 2 {
		rec.Error = fmt.Sprintf("Alertmanager answered %d", resp.StatusCode)
		return errors.New(rec.Error)
	}
	return nil
}

func (a *Alertmanager) kept(body []byte) *audit.Body {
	limit := int64(len(body))
	if a.cfg.BodyLimit != nil {
		limit = a.cfg.BodyLimit()
	}
	c, r, err := audit.CaptureBody(bytes.NewReader(body), limit)
	if err != nil {
		return nil
	}
	_, _ = io.Copy(io.Discard, r)
	s := c.Summary()
	return &s
}

// bearerValue reports whether s can follow "Bearer " as it is: visible
// ASCII, with no spaces.
func bearerValue(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] <= ' ' || s[i] > '~' {
			return false
		}
	}
	return true
}
