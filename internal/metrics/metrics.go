// Package metrics provides Prometheus metric collectors for traceroute results.
package metrics

import (
	"context"
	"errors"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/fmotalleb/traceroute-exporter/internal/traceroute"
)

// Common label name constants used across metric definitions.
const (
	labelEndHop        = "end_hop"
	labelReason        = "reason"
	labelAddress       = "address"
	labelHop           = "hop"
	labelParent        = "parent"
	labelParentAddress = "parent_address"
	labelProbe         = "probe"
	labelVersion       = "version"
)

// metricDef pairs a Desc with its variable label names so we can extract
// values from a map in the correct positional order for MustNewConstMetric.
type metricDef struct {
	desc   *prometheus.Desc
	labels []string
}

// Metric descriptors – defined once, reused across all collectors.
var (
	defProbeSuccess = metricDef{prometheus.NewDesc(
		"traceroute_probe_success",
		"1 if the final destination was reached by traceroute, 0 otherwise.",
		nil, nil,
	), nil}
	defProbeDuration = metricDef{prometheus.NewDesc(
		"traceroute_probe_duration_seconds",
		"Time spent running the traceroute probe.",
		nil, nil,
	), nil}
	defCommandSuccess = metricDef{prometheus.NewDesc(
		"traceroute_command_success",
		"1 if the traceroute command exited successfully, 0 otherwise. Loop give-up is not a command failure.",
		nil, nil,
	), nil}
	defCommandExitCode = metricDef{prometheus.NewDesc(
		"traceroute_command_exit_code",
		"Exit code from traceroute. -1 means start/build failure, -2 means timeout.",
		nil, nil,
	), nil}
	defParseSuccess = metricDef{prometheus.NewDesc(
		"traceroute_output_parse_success",
		"1 if at least one hop was parsed from traceroute output, 0 otherwise.",
		nil, nil,
	), nil}
	defHops = metricDef{prometheus.NewDesc(
		"traceroute_hops",
		"Highest hop number parsed from traceroute output.",
		nil, nil,
	), nil}
	defLoopDetected = metricDef{prometheus.NewDesc(
		"traceroute_loop_detected",
		"1 if the emitted trace contains a repeated routing-loop pattern, 0 otherwise.",
		nil, nil,
	), nil}
	defLoopGiveup = metricDef{prometheus.NewDesc(
		"traceroute_loop_giveup",
		"1 if tracing stopped early because the repeated-loop threshold was reached, 0 otherwise.",
		nil, nil,
	), nil}
	defLoopInfo = metricDef{prometheus.NewDesc(
		"traceroute_loop_info",
		"Information about a detected routing loop. Pattern contains responding node ids in the repeated suffix.",
		[]string{"start_hop", labelEndHop, "length", "repeats", "pattern"}, nil,
	), []string{"start_hop", labelEndHop, "length", "repeats", "pattern"}}
	defProbeErrorInfo = metricDef{prometheus.NewDesc(
		"traceroute_probe_error_info",
		"Error information for failed probes. The reason label is intentionally low-cardinality.",
		[]string{labelReason}, nil,
	), []string{labelReason}}
	defTargetInfo = metricDef{prometheus.NewDesc(
		"traceroute_target_info",
		"Intended traceroute destination. Prometheus relabeling normally adds the scraped target label.",
		[]string{"hostname", labelAddress, "resolved_address", "port", "reached"}, nil,
	), []string{"hostname", labelAddress, "resolved_address", "port", "reached"}}
	defNodeInfo = metricDef{prometheus.NewDesc(
		"traceroute_node_info",
		"One sample per graph node. The hostname label is always present; non-responding hops use no-reply-hop-NN.",
		[]string{"id", labelHop, "node", "hostname", labelAddress, "responded", "role"}, nil,
	), []string{"id", labelHop, "node", "hostname", labelAddress, "responded", "role"}}
	defEdgeInfo = metricDef{prometheus.NewDesc(
		"traceroute_edge_info",
		"Edge samples for Grafana node graph. Labels: id, source, target.",
		[]string{
			"id", "source", "target", labelParent, "node", "parent_hop", "target_hop",
			"parent_hostname", "target_hostname", labelParentAddress, "target_address", "target_responded",
		}, nil,
	), []string{
		"id", "source", "target", labelParent, "node", "parent_hop", "target_hop",
		"parent_hostname", "target_hostname", labelParentAddress, "target_address", "target_responded",
	}}
	defHopRTT = metricDef{prometheus.NewDesc(
		"traceroute_hop_rtt_seconds",
		"Round-trip time for each responding probe.",
		[]string{labelHop, "node", "hostname", labelAddress, labelProbe, "responded"}, nil,
	), []string{labelHop, "node", "hostname", labelAddress, labelProbe, "responded"}}
	defHopRTTAvg = metricDef{prometheus.NewDesc(
		"traceroute_hop_rtt_avg_seconds",
		"Average round-trip time per responding node.",
		[]string{labelHop, "node", "hostname", labelAddress, "responded"}, nil,
	), []string{labelHop, "node", "hostname", labelAddress, "responded"}}
	defHopLossRatio = metricDef{prometheus.NewDesc(
		"traceroute_hop_probe_loss_ratio",
		"Fraction of probes that did not return a hostname/address for the hop.",
		[]string{labelHop, "node", "hostname", labelAddress, "responded"}, nil,
	), []string{labelHop, "node", "hostname", labelAddress, "responded"}}
	defExporterBuildInfo = metricDef{prometheus.NewDesc(
		"traceroute_exporter_build_info",
		"Static build information for this exporter.",
		[]string{labelVersion}, nil,
	), []string{labelVersion}}
)

// allDescs is a pre-allocated slice of every metric descriptor.
// Used by Describe() so no allocation happens per call.
var allDescs = func() []*prometheus.Desc {
	defs := []metricDef{
		defProbeSuccess, defProbeDuration, defCommandSuccess, defCommandExitCode,
		defParseSuccess, defHops, defLoopDetected, defLoopGiveup, defLoopInfo,
		defProbeErrorInfo, defTargetInfo, defNodeInfo, defEdgeInfo,
		defHopRTT, defHopRTTAvg, defHopLossRatio,
	}
	out := make([]*prometheus.Desc, len(defs))
	for i, d := range defs {
		out[i] = d.desc
	}
	return out
}()

// TraceCollector implements prometheus.Collector. It holds pre-built
// metrics that are emitted on each Collect() call. A fresh instance
// (and fresh Registry) is created per /trace request.
type TraceCollector struct {
	metrics []prometheus.Metric
}

// Describe is required by the Collector interface.
func (c *TraceCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, desc := range allDescs {
		ch <- desc
	}
}

// Collect sends the pre-built metrics to the channel.
func (c *TraceCollector) Collect(ch chan<- prometheus.Metric) {
	for _, m := range c.metrics {
		ch <- m
	}
}

// NewTraceCollector builds a TraceCollector from trace results and base labels.
// traceErr should be the original error from ProbeTrace (not pre-normalised).
func NewTraceCollector(base map[string]string, trace traceroute.TraceResult, traceErr error, duration float64, opts traceroute.TraceOptions, spec traceroute.TargetSpec, sourceID string) *TraceCollector {
	var m []prometheus.Metric

	// Static meta-metrics
	m = append(m, newMetric(defProbeDuration, duration, base))
	m = append(m, newMetric(defHops, float64(traceroute.LastHop(trace.Hops)), base))

	commandSuccess := 0.0
	if traceErr == nil {
		commandSuccess = 1
	}
	m = append(m, newMetric(defCommandSuccess, commandSuccess, base))

	parseSuccess := 0.0
	if len(trace.Hops) > 0 {
		parseSuccess = 1
	}
	m = append(m, newMetric(defParseSuccess, parseSuccess, base))

	probeSuccess := 0.0
	if trace.Reached {
		probeSuccess = 1
	}
	m = append(m, newMetric(defProbeSuccess, probeSuccess, base))

	m = append(m, newMetric(defLoopDetected, traceroute.BoolFloat(trace.Loop.Detected), base))
	m = append(m, newMetric(defLoopGiveup, traceroute.BoolFloat(trace.Loop.GiveUp), base))

	// Loop info (conditional)
	if trace.Loop.Detected {
		m = append(m, newMetric(defLoopInfo, 1, mergeStr(base, map[string]string{
			"start_hop": strconv.Itoa(trace.Loop.StartHop),
			"end_hop":   strconv.Itoa(trace.Loop.EndHop),
			"length":    strconv.Itoa(trace.Loop.Length),
			"repeats":   strconv.Itoa(trace.Loop.Repeats),
			"pattern":   trace.Loop.Pattern,
		})))
	}

	// Error info (conditional)
	if traceErr != nil {
		reason := "command_failed"
		if errors.Is(traceErr, context.Canceled) || errors.Is(traceErr, context.DeadlineExceeded) {
			reason = "timeout"
		}
		m = append(m, newMetric(defProbeErrorInfo, 1, mergeStr(base, map[string]string{"reason": reason})))
	}
	if len(trace.Hops) == 0 && traceErr == nil {
		m = append(m, newMetric(defProbeErrorInfo, 1, mergeStr(base, map[string]string{"reason": "parse_failed"})))
	}
	if trace.Loop.GiveUp {
		m = append(m, newMetric(defProbeErrorInfo, 1, mergeStr(base, map[string]string{"reason": "routing_loop_giveup"})))
	}

	// Target info
	m = append(m, newMetric(defTargetInfo, 1, mergeStr(base, map[string]string{
		"hostname":         traceroute.Fallback(trace.DestinationHost, spec.Host),
		"address":          traceroute.Fallback(trace.DestinationAddress, trace.ResolvedAddress),
		"resolved_address": trace.ResolvedAddress,
		"port":             spec.Port,
		"reached":          traceroute.BoolString(trace.Reached),
	})))

	// Source node (hop 0)
	source := &traceroute.Node{
		ID:        sourceID,
		Hop:       0,
		Hostname:  sourceID,
		Address:   "",
		Responded: true,
		Role:      "source",
	}
	m = append(m, mustNode(base, source))

	// Hop nodes + RTT + loss
	for _, hop := range trace.Hops {
		for _, node := range hop.Nodes {
			m = append(m, mustNode(base, node))

			loss := traceroute.LossRatio(hop, opts.Queries)
			m = append(m, newMetric(defHopLossRatio, loss, mergeStr(base, map[string]string{
				"hop":       strconv.Itoa(node.Hop),
				"node":      node.ID,
				"hostname":  node.Hostname,
				"address":   node.Address,
				"responded": traceroute.BoolString(node.Responded),
			})))

			for i, rtt := range node.RTTs {
				m = append(m, newMetric(defHopRTT, rtt, mergeStr(base, map[string]string{
					"hop":       strconv.Itoa(node.Hop),
					"node":      node.ID,
					"hostname":  node.Hostname,
					"address":   node.Address,
					"probe":     strconv.Itoa(i + 1),
					"responded": traceroute.BoolString(node.Responded),
				})))
			}

			if avg, ok := traceroute.AvgRTT(node.RTTs); ok {
				m = append(m, newMetric(defHopRTTAvg, avg, mergeStr(base, map[string]string{
					"hop":       strconv.Itoa(node.Hop),
					"node":      node.ID,
					"hostname":  node.Hostname,
					"address":   node.Address,
					"responded": traceroute.BoolString(node.Responded),
				})))
			}
		}
	}

	// Edges (Grafana node graph)
	for _, edge := range traceroute.BuildEdges(source, trace.Hops) {
		edgeID := edge.Parent.ID + "_to_" + edge.Node.ID
		m = append(m, newMetric(defEdgeInfo, 1, mergeStr(base, map[string]string{
			"id":               edgeID,
			"source":           edge.Parent.ID,
			"target":           edge.Node.ID,
			"parent":           edge.Parent.ID,
			"node":             edge.Node.ID,
			"parent_hop":       strconv.Itoa(edge.Parent.Hop),
			"target_hop":       strconv.Itoa(edge.Node.Hop),
			"parent_hostname":  traceroute.Fallback(edge.Parent.Hostname, edge.Parent.ID),
			"target_hostname":  traceroute.Fallback(edge.Node.Hostname, edge.Node.ID),
			"parent_address":   edge.Parent.Address,
			"target_address":   edge.Node.Address,
			"target_responded": traceroute.BoolString(edge.Node.Responded),
		})))
	}

	return &TraceCollector{metrics: m}
}

// NewFailureCollector builds a TraceCollector for a failed probe.
func NewFailureCollector(base map[string]string, reason string, exitCode int, duration float64) *TraceCollector {
	var m []prometheus.Metric
	m = append(m, newMetric(defProbeDuration, duration, base))
	m = append(m, newMetric(defCommandSuccess, 0, base))
	m = append(m, newMetric(defCommandExitCode, float64(exitCode), base))
	m = append(m, newMetric(defParseSuccess, 0, base))
	m = append(m, newMetric(defProbeSuccess, 0, base))
	m = append(m, newMetric(defLoopDetected, 0, base))
	m = append(m, newMetric(defLoopGiveup, 0, base))
	m = append(m, newMetric(defProbeErrorInfo, 1, mergeStr(base, map[string]string{"reason": reason})))
	return &TraceCollector{metrics: m}
}

// NewBuildInfoCollector creates a collector for the static /metrics endpoint.
func NewBuildInfoCollector() *TraceCollector {
	return &TraceCollector{
		metrics: []prometheus.Metric{
			newMetric(defExporterBuildInfo, 1, map[string]string{"version": "dev"}),
		},
	}
}

// --- helpers ---

// newMetric creates a Gauge metric from a metricDef and a label map.
func newMetric(def metricDef, value float64, labels map[string]string) prometheus.Metric {
	vals := extractValues(def.labels, labels)
	return prometheus.MustNewConstMetric(def.desc, prometheus.GaugeValue, value, vals...)
}

func mustNode(base map[string]string, node *traceroute.Node) prometheus.Metric {
	return newMetric(defNodeInfo, 1, mergeStr(base, map[string]string{
		"id":        node.ID,
		"hop":       strconv.Itoa(node.Hop),
		"node":      node.ID,
		"hostname":  traceroute.Fallback(node.Hostname, node.ID),
		"address":   node.Address,
		"responded": traceroute.BoolString(node.Responded),
		"role":      traceroute.Fallback(node.Role, "hop"),
	}))
}

// extractValues returns label values from the map in the order of names.
func extractValues(names []string, labels map[string]string) []string {
	if len(names) == 0 {
		return nil
	}
	vals := make([]string, len(names))
	for i, name := range names {
		vals[i] = labels[name]
	}
	return vals
}

// mergeStr merges base + extra into a new map (extra wins).
func mergeStr(base, extra map[string]string) map[string]string {
	out := make(map[string]string, len(base)+len(extra))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}
