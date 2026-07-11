package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/fmotalleb/go-tools/log"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"

	"github.com/fmotalleb/traceroute-exporter/internal/config"
	"github.com/fmotalleb/traceroute-exporter/internal/dashboard"
	"github.com/fmotalleb/traceroute-exporter/internal/metrics"
	"github.com/fmotalleb/traceroute-exporter/internal/traceroute"
)

// Exporter handles HTTP requests for the traceroute exporter
type Exporter struct {
	cfg *config.Config
}

// NewExporter creates an Exporter
func NewExporter(cfg *config.Config) *Exporter {
	return &Exporter{cfg: cfg}
}

// Index handles the root path
func (e *Exporter) Index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	exampleTrace := html.EscapeString("/trace?target=example.com:443")
	exampleDashboard := html.EscapeString("/dashboard?target=example.com:443")
	_, _ = fmt.Fprintf(w, `<!doctype html>
<html><head><title>traceroute exporter</title></head>
<body>
<h1>traceroute exporter</h1>
<p>Probe endpoint: <a href="%s">%s</a></p>
<p>Embedded dashboard: <a href="%s">%s</a></p>
<p>Query parameters: <code>target</code> required; optional <code>method=tcp|icmp|udp|auto</code>, <code>max_hops</code>, <code>queries</code>, <code>wait</code>, <code>timeout</code>, <code>ip_family=4|6</code>, <code>loop_max_repeats</code>, <code>debug=1</code>.</p>
<p>Loop detection gives up after <code>%d</code> repeated cycle(s) by default. Use <code>loop_max_repeats=0</code> to disable for one probe.</p>
<p>Prometheus should scrape <code>/trace</code> with the target passed as <code>__param_target</code>, blackbox-exporter style.</p>
<p>Web config: pass <code>--web.config.file=/path/to/web.yml</code> or place <code>web.yml</code> next to the binary for TLS and bcrypt basic auth.</p>
</body></html>`, exampleTrace, exampleTrace, exampleDashboard, exampleDashboard, e.cfg.DefaultLoopMaxRepeats)
}

// Healthz handles the health check endpoint
func (e *Exporter) Healthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("ok\n"))
}

// Metrics handles the /metrics endpoint – serves the static build-info gauge
// via a fresh Prometheus registry and the standard promhttp handler.
func (e *Exporter) Metrics(w http.ResponseWriter, r *http.Request) {
	reg := prometheus.NewRegistry()
	reg.MustRegister(metrics.NewBuildInfoCollector())
	promhttp.HandlerFor(reg, promhttp.HandlerOpts{}).ServeHTTP(w, r)
}

// Dashboard handles the dashboard endpoint
func (e *Exporter) Dashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	target := strings.TrimSpace(r.URL.Query().Get("target"))
	if target == "" {
		target = "example.com:443"
	}
	targetJSON, err := json.Marshal(target)
	if err != nil {
		targetJSON = []byte(`"example.com:443"`)
	}
	page := strings.ReplaceAll(dashboard.DashboardHTML, "{{TARGET_JSON}}", string(targetJSON))
	page = strings.ReplaceAll(page, "{{DEFAULT_LOOP_REPEATS}}", strconv.Itoa(e.cfg.DefaultLoopMaxRepeats))
	_, _ = w.Write([]byte(page))
}

// Trace handles the /trace endpoint – runs a traceroute and exposes the
// results as Prometheus metrics via a fresh registry and promhttp handler.
func (e *Exporter) Trace(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := log.FromContext(ctx)
	started := time.Now()
	q := r.URL.Query()

	targetParam := strings.TrimSpace(q.Get("target"))
	opts := traceroute.OptionsFromQuery(q, traceroute.Options{
		DefaultMethod:         e.cfg.DefaultMethod,
		DefaultMaxHops:        e.cfg.DefaultMaxHops,
		DefaultQueries:        e.cfg.DefaultQueries,
		DefaultWait:           e.cfg.DefaultWait,
		DefaultTimeout:        e.cfg.DefaultTimeout,
		DefaultIPFamily:       e.cfg.DefaultIPFamily,
		DefaultLoopMaxRepeats: e.cfg.DefaultLoopMaxRepeats,
	})

	var collector *metrics.TraceCollector

	if targetParam == "" {
		base := traceroute.BaseLabels(opts, traceroute.TargetSpec{})
		collector = metrics.NewFailureCollector(base, "missing_target", -1, time.Since(started).Seconds())
		w.WriteHeader(http.StatusBadRequest)
	} else {
		spec, err := traceroute.ParseTarget(targetParam)
		if err != nil {
			base := traceroute.BaseLabels(opts, traceroute.TargetSpec{Original: targetParam})
			collector = metrics.NewFailureCollector(base, "invalid_target", -1, time.Since(started).Seconds())
		} else {
			if opts.Method == "auto" {
				if spec.Port != "" {
					opts.Method = "tcp"
				} else {
					opts.Method = "icmp"
				}
			}

			traceCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
			defer cancel()

			resolved := traceroute.ResolveTarget(traceCtx, spec.Host, opts.IPFamily)
			trace, traceErr := traceroute.ProbeTrace(traceCtx, spec, opts, resolved)

			base := traceroute.BaseLabels(opts, spec)
			if trace.DestinationHost == "" {
				trace.DestinationHost = spec.Host
			}
			if trace.DestinationPort == "" {
				trace.DestinationPort = spec.Port
			}
			if trace.ResolvedAddress == "" {
				trace.ResolvedAddress = resolved
			}
			if trace.DestinationAddress == "" {
				trace.DestinationAddress = resolved
			}
			trace.Reached = traceroute.ComputeReached(trace, spec)

			// Normalise the error for label purposes.
			var traceErrNorm error
			if traceErr != nil {
				traceErrNorm = traceErr
				if errors.Is(traceCtx.Err(), context.DeadlineExceeded) {
					traceErrNorm = errors.New("context deadline exceeded")
				}
			}

			collector = metrics.NewTraceCollector(base, trace, traceErrNorm, time.Since(started).Seconds(), opts, spec, e.cfg.SourceID)

			logger.Debug("trace completed",
				zap.String("target", targetParam),
				zap.Bool("reached", trace.Reached),
				zap.Int("hops", len(trace.Hops)),
				zap.Duration("duration", time.Since(started)),
			)
		}
	}

	// Create a fresh registry, register the collector, serve via promhttp.
	reg := prometheus.NewRegistry()
	reg.MustRegister(collector)
	promhttp.HandlerFor(reg, promhttp.HandlerOpts{
		ErrorHandling: promhttp.HTTPErrorOnError,
	}).ServeHTTP(w, r)
}
