package metrics

import (
	"sort"
	"strconv"
	"strings"

	"github.com/fmotalleb/traceroute-exporter/internal/traceroute"
)

// WriteMetricHeader writes Prometheus metric headers
func WriteMetricHeader(b *strings.Builder) {
	b.WriteString("# HELP traceroute_probe_success 1 if the final destination was reached by traceroute, 0 otherwise.\n")
	b.WriteString("# TYPE traceroute_probe_success gauge\n")
	b.WriteString("# HELP traceroute_probe_duration_seconds Time spent running the traceroute probe.\n")
	b.WriteString("# TYPE traceroute_probe_duration_seconds gauge\n")
	b.WriteString("# HELP traceroute_command_success 1 if the traceroute command exited successfully, 0 otherwise. Loop give-up is not a command failure.\n")
	b.WriteString("# TYPE traceroute_command_success gauge\n")
	b.WriteString("# HELP traceroute_command_exit_code Exit code from traceroute. -1 means start/build failure, -2 means timeout.\n")
	b.WriteString("# TYPE traceroute_command_exit_code gauge\n")
	b.WriteString("# HELP traceroute_output_parse_success 1 if at least one hop was parsed from traceroute output, 0 otherwise.\n")
	b.WriteString("# TYPE traceroute_output_parse_success gauge\n")
	b.WriteString("# HELP traceroute_hops Highest hop number parsed from traceroute output.\n")
	b.WriteString("# TYPE traceroute_hops gauge\n")
	b.WriteString("# HELP traceroute_loop_detected 1 if the emitted trace contains a repeated routing-loop pattern, 0 otherwise.\n")
	b.WriteString("# TYPE traceroute_loop_detected gauge\n")
	b.WriteString("# HELP traceroute_loop_giveup 1 if tracing stopped early because the repeated-loop threshold was reached, 0 otherwise.\n")
	b.WriteString("# TYPE traceroute_loop_giveup gauge\n")
	b.WriteString("# HELP traceroute_loop_info Information about a detected routing loop. Pattern contains responding node ids in the repeated suffix.\n")
	b.WriteString("# TYPE traceroute_loop_info gauge\n")
	b.WriteString("# HELP traceroute_probe_error_info Error information for failed probes. The reason label is intentionally low-cardinality.\n")
	b.WriteString("# TYPE traceroute_probe_error_info gauge\n")
	b.WriteString("# HELP traceroute_target_info Intended traceroute destination. Prometheus relabeling normally adds the scraped target label.\n")
	b.WriteString("# TYPE traceroute_target_info gauge\n")
	b.WriteString("# HELP traceroute_node_info One sample per graph node. The hostname label is always present; non-responding hops use no-reply-hop-NN.\n")
	b.WriteString("# TYPE traceroute_node_info gauge\n")
	b.WriteString("# HELP traceroute_tree_edge_info Parent-child edge samples for Grafana tree graphs. Use labels parent and node.\n")
	b.WriteString("# TYPE traceroute_tree_edge_info gauge\n")
	b.WriteString("# HELP traceroute_edge_info Source-destination edge samples for generic graph panels. Uses destination instead of target to avoid colliding with the Prometheus scrape target label.\n")
	b.WriteString("# TYPE traceroute_edge_info gauge\n")
	b.WriteString("# HELP traceroute_hop_rtt_seconds Round-trip time for each responding probe.\n")
	b.WriteString("# TYPE traceroute_hop_rtt_seconds gauge\n")
	b.WriteString("# HELP traceroute_hop_rtt_avg_seconds Average round-trip time per responding node.\n")
	b.WriteString("# TYPE traceroute_hop_rtt_avg_seconds gauge\n")
	b.WriteString("# HELP traceroute_hop_probe_loss_ratio Fraction of probes that did not return a hostname/address for the hop.\n")
	b.WriteString("# TYPE traceroute_hop_probe_loss_ratio gauge\n")
}

// WriteNodeMetric writes a node metric
func WriteNodeMetric(b *strings.Builder, base map[string]string, node *traceroute.Node) {
	WriteMetric(b, "traceroute_node_info", traceroute.MergeLabels(base, map[string]string{
		"hop":       strconv.Itoa(node.Hop),
		"node":      node.ID,
		"hostname":  traceroute.Fallback(node.Hostname, node.ID),
		"address":   node.Address,
		"responded": traceroute.BoolString(node.Responded),
		"role":      traceroute.Fallback(node.Role, "hop"),
	}), 1)
}

// WriteMetric writes a single Prometheus metric line
func WriteMetric(b *strings.Builder, name string, labels map[string]string, value float64) {
	b.WriteString(name)
	if len(labels) > 0 {
		b.WriteString(LabelsToString(labels))
	}
	b.WriteByte(' ')
	b.WriteString(strconv.FormatFloat(value, 'g', -1, 64))
	b.WriteByte('\n')
}

// LabelsToString converts a label map to Prometheus label format
func LabelsToString(labels map[string]string) string {
	keys := make([]string, 0, len(labels))
	for k := range labels {
		if k == "" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(k)
		b.WriteString("=\"")
		b.WriteString(EscapeLabel(labels[k]))
		b.WriteByte('"')
	}
	b.WriteByte('}')
	return b.String()
}

// EscapeLabel escapes special characters in a label value
func EscapeLabel(s string) string {
	s = strings.ReplaceAll(s, `\\`, `\\\\`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return s
}

// PromComment formats a string for use as a Prometheus comment
func PromComment(s string) string {
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	return strings.TrimSpace(s)
}
