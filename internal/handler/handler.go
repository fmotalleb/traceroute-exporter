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

// NewExporter creates a new Exporter
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

// Metrics handles the metrics endpoint
func (e *Exporter) Metrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	var b strings.Builder
	b.WriteString("# HELP traceroute_exporter_build_info Static build information for this exporter.\n")
	b.WriteString("# TYPE traceroute_exporter_build_info gauge\n")
	metrics.WriteMetric(&b, "traceroute_exporter_build_info", map[string]string{"version": "dev"}, 1)
	_, _ = w.Write([]byte(b.String()))
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

// Trace handles the trace endpoint
func (e *Exporter) Trace(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := log.FromContext(ctx)
	started := time.Now()
	q := r.URL.Query()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

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

	var b strings.Builder
	metrics.WriteMetricHeader(&b)

	if targetParam == "" {
		base := traceroute.BaseLabels(opts, traceroute.TargetSpec{})
		writeFailureMetrics(&b, base, started, "missing_target", -1)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(b.String()))
		return
	}

	spec, err := traceroute.ParseTarget(targetParam)
	if err != nil {
		base := traceroute.BaseLabels(opts, traceroute.TargetSpec{Original: targetParam})
		writeFailureMetrics(&b, base, started, "invalid_target", -1)
		_, _ = w.Write([]byte(b.String()))
		return
	}

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

	commandSuccess := 0.0
	if traceErr == nil {
		commandSuccess = 1
	}
	parseSuccess := 0.0
	if len(trace.Hops) > 0 {
		parseSuccess = 1
	}
	probeSuccess := 0.0
	if trace.Reached {
		probeSuccess = 1
	}

	metrics.WriteMetric(&b, "traceroute_probe_duration_seconds", base, time.Since(started).Seconds())
	metrics.WriteMetric(&b, "traceroute_command_success", base, commandSuccess)
	metrics.WriteMetric(&b, "traceroute_output_parse_success", base, parseSuccess)
	metrics.WriteMetric(&b, "traceroute_probe_success", base, probeSuccess)
	metrics.WriteMetric(&b, "traceroute_hops", base, float64(traceroute.LastHop(trace.Hops)))
	metrics.WriteMetric(&b, "traceroute_loop_detected", base, traceroute.BoolFloat(trace.Loop.Detected))
	metrics.WriteMetric(&b, "traceroute_loop_giveup", base, traceroute.BoolFloat(trace.Loop.GiveUp))
	if trace.Loop.Detected {
		metrics.WriteMetric(&b, "traceroute_loop_info", traceroute.MergeLabels(base, map[string]string{
			"start_hop": strconv.Itoa(trace.Loop.StartHop),
			"end_hop":   strconv.Itoa(trace.Loop.EndHop),
			"length":    strconv.Itoa(trace.Loop.Length),
			"repeats":   strconv.Itoa(trace.Loop.Repeats),
			"pattern":   trace.Loop.Pattern,
		}), 1)
	}

	if traceErr != nil {
		reason := "command_failed"
		if errors.Is(traceCtx.Err(), context.DeadlineExceeded) {
			reason = "timeout"
		}
		metrics.WriteMetric(&b, "traceroute_probe_error_info", traceroute.MergeLabels(base, map[string]string{"reason": reason}), 1)
	}
	if len(trace.Hops) == 0 && traceErr == nil {
		metrics.WriteMetric(&b, "traceroute_probe_error_info", traceroute.MergeLabels(base, map[string]string{"reason": "parse_failed"}), 1)
	}
	if trace.Loop.GiveUp {
		metrics.WriteMetric(&b, "traceroute_probe_error_info", traceroute.MergeLabels(base, map[string]string{"reason": "routing_loop_giveup"}), 1)
	}

	metrics.WriteMetric(&b, "traceroute_target_info", traceroute.MergeLabels(base, map[string]string{
		"hostname":         traceroute.Fallback(trace.DestinationHost, spec.Host),
		"address":          traceroute.Fallback(trace.DestinationAddress, trace.ResolvedAddress),
		"resolved_address": trace.ResolvedAddress,
		"port":             spec.Port,
		"reached":          traceroute.BoolString(trace.Reached),
	}), 1)

	source := &traceroute.Node{
		ID:        e.cfg.SourceID,
		Hop:       0,
		Hostname:  traceroute.Fallback(e.cfg.SourceHostname, e.cfg.SourceID),
		Address:   e.cfg.SourceAddress,
		Responded: true,
		Role:      "source",
	}
	metrics.WriteNodeMetric(&b, base, source)

	for _, hop := range trace.Hops {
		for _, node := range hop.Nodes {
			metrics.WriteNodeMetric(&b, base, node)
			loss := traceroute.LossRatio(hop, opts.Queries)
			metrics.WriteMetric(&b, "traceroute_hop_probe_loss_ratio", traceroute.MergeLabels(base, map[string]string{
				"hop":       strconv.Itoa(node.Hop),
				"node":      node.ID,
				"hostname":  node.Hostname,
				"address":   node.Address,
				"responded": traceroute.BoolString(node.Responded),
			}), loss)
			for i, rtt := range node.RTTs {
				metrics.WriteMetric(&b, "traceroute_hop_rtt_seconds", traceroute.MergeLabels(base, map[string]string{
					"hop":       strconv.Itoa(node.Hop),
					"node":      node.ID,
					"hostname":  node.Hostname,
					"address":   node.Address,
					"probe":     strconv.Itoa(i + 1),
					"responded": traceroute.BoolString(node.Responded),
				}), rtt)
			}
			if avg, ok := traceroute.AvgRTT(node.RTTs); ok {
				metrics.WriteMetric(&b, "traceroute_hop_rtt_avg_seconds", traceroute.MergeLabels(base, map[string]string{
					"hop":       strconv.Itoa(node.Hop),
					"node":      node.ID,
					"hostname":  node.Hostname,
					"address":   node.Address,
					"responded": traceroute.BoolString(node.Responded),
				}), avg)
			}
		}
	}

	for _, edge := range traceroute.BuildEdges(source, trace.Hops) {
		metrics.WriteMetric(&b, "traceroute_tree_edge_info", traceroute.MergeLabels(base, map[string]string{
			"parent":          edge.Parent.ID,
			"node":            edge.Node.ID,
			"parent_hop":      strconv.Itoa(edge.Parent.Hop),
			"node_hop":        strconv.Itoa(edge.Node.Hop),
			"parent_hostname": traceroute.Fallback(edge.Parent.Hostname, edge.Parent.ID),
			"node_hostname":   traceroute.Fallback(edge.Node.Hostname, edge.Node.ID),
			"parent_address":  edge.Parent.Address,
			"node_address":    edge.Node.Address,
			"node_responded":  traceroute.BoolString(edge.Node.Responded),
		}), 1)
		metrics.WriteMetric(&b, "traceroute_edge_info", traceroute.MergeLabels(base, map[string]string{
			"source":                edge.Parent.ID,
			"destination":           edge.Node.ID,
			"source_hop":            strconv.Itoa(edge.Parent.Hop),
			"destination_hop":       strconv.Itoa(edge.Node.Hop),
			"source_hostname":       traceroute.Fallback(edge.Parent.Hostname, edge.Parent.ID),
			"destination_hostname":  traceroute.Fallback(edge.Node.Hostname, edge.Node.ID),
			"source_address":        edge.Parent.Address,
			"destination_address":   edge.Node.Address,
			"destination_responded": traceroute.BoolString(edge.Node.Responded),
		}), 1)
	}



	logger.Debug("trace completed",
		zap.String("target", targetParam),
		zap.Bool("reached", trace.Reached),
		zap.Int("hops", len(trace.Hops)),
		zap.Duration("duration", time.Since(started)),
	)

	_, _ = w.Write([]byte(b.String()))
}

func writeFailureMetrics(b *strings.Builder, base map[string]string, started time.Time, reason string, exitCode int) {
	metrics.WriteMetric(b, "traceroute_probe_duration_seconds", base, time.Since(started).Seconds())
	metrics.WriteMetric(b, "traceroute_command_success", base, 0)
	metrics.WriteMetric(b, "traceroute_command_exit_code", base, float64(exitCode))
	metrics.WriteMetric(b, "traceroute_output_parse_success", base, 0)
	metrics.WriteMetric(b, "traceroute_probe_success", base, 0)
	metrics.WriteMetric(b, "traceroute_loop_detected", base, 0)
	metrics.WriteMetric(b, "traceroute_loop_giveup", base, 0)
	metrics.WriteMetric(b, "traceroute_probe_error_info", traceroute.MergeLabels(base, map[string]string{"reason": reason}), 1)
}
