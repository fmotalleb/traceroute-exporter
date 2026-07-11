package traceroute

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/fmotalleb/go-tools/log"
	"go.uber.org/zap"
)

// OptionsFromQuery extracts trace options from URL query parameters
func OptionsFromQuery(q url.Values, defaults Options) TraceOptions {
	loopMaxRepeats := ClampInt(QueryInt(q, "loop_max_repeats", defaults.DefaultLoopMaxRepeats), 0, 100)
	switch strings.ToLower(strings.TrimSpace(q.Get("loop_detection"))) {
	case "0", "false", "off", "no", "disabled":
		loopMaxRepeats = 0
	}

	return TraceOptions{
		Method:         NormalizeMethod(QueryString(q, "method", defaults.DefaultMethod)),
		MaxHops:        ClampInt(QueryInt(q, "max_hops", defaults.DefaultMaxHops), 1, 255),
		Queries:        ClampInt(QueryInt(q, "queries", defaults.DefaultQueries), 1, 10),
		Wait:           QueryDuration(q, "wait", defaults.DefaultWait),
		Timeout:        QueryDuration(q, "timeout", defaults.DefaultTimeout),
		IPFamily:       NormalizeIPFamily(QueryString(q, "ip_family", defaults.DefaultIPFamily)),
		LoopMaxRepeats: loopMaxRepeats,
		Debug:          q.Get("debug") == "1" || strings.EqualFold(q.Get("debug"), "true"),
	}
}

// Options holds default configuration options
type Options struct {
	DefaultMethod         string
	DefaultMaxHops        int
	DefaultQueries        int
	DefaultWait           time.Duration
	DefaultTimeout        time.Duration
	DefaultIPFamily       string
	DefaultLoopMaxRepeats int
}

// BaseLabels creates base labels for metrics
func BaseLabels(opts TraceOptions, spec TargetSpec) map[string]string {
	return map[string]string{
		"method":           opts.Method,
		"ip_family":        opts.IPFamily,
		"target_host":      spec.Host,
		"target_port":      spec.Port,
		"loop_max_repeats": strconv.Itoa(opts.LoopMaxRepeats),
	}
}

// ProbeTrace executes a traceroute probe using native Go packet operations
// without depending on the system traceroute binary.
func ProbeTrace(ctx context.Context, spec TargetSpec, opts TraceOptions, resolved string) (TraceResult, error) {
	logger := log.FromContext(ctx)
	trace := NewTraceResult(spec, resolved)

	// Build the target address for native probing
	target := spec.Host
	if resolved != "" {
		target = resolved
	}

	// For auto method, resolve based on port presence
	method := NormalizeMethod(opts.Method)
	if method == "auto" {
		if spec.Port != "" {
			method = "tcp"
		} else {
			method = "icmp"
		}
		opts.Method = method
	}

	logger.Debug("starting native traceroute",
		zap.String("target", target),
		zap.String("method", method),
		zap.Int("max_hops", opts.MaxHops),
		zap.Int("queries", opts.Queries),
		zap.Duration("timeout", opts.Timeout),
	)

	// Execute native traceroute
	hops, err := NativeTraceroute(ctx, target, opts)
	if err != nil {
		logger.Error("native traceroute failed", zap.Error(err))
		trace.RawOutput = fmt.Sprintf("error: %v", err)
		return trace, err
	}

	trace.Hops = hops
	trace.Loop = DetectLoop(trace.Hops, opts.LoopMaxRepeats)
	if trace.Loop.GiveUp {
		trace.Hops = TrimHopsAfter(trace.Hops, trace.Loop.EndHop)
	}

	logger.Debug("native traceroute completed",
		zap.Int("hops", len(trace.Hops)),
		zap.Bool("reached", trace.Reached),
	)

	return trace, nil
}

// ParseTarget parses a raw target string into a TargetSpec
func ParseTarget(raw string) (TargetSpec, error) {
	spec := TargetSpec{Original: strings.TrimSpace(raw)}
	if spec.Original == "" {
		return spec, errors.New("empty target")
	}

	if strings.Contains(spec.Original, "://") {
		u, err := url.Parse(spec.Original)
		if err != nil {
			return spec, err
		}
		spec.Host = u.Hostname()
		spec.Port = u.Port()
	} else {
		if h, p, err := net.SplitHostPort(spec.Original); err == nil {
			spec.Host = strings.Trim(h, "[]")
			spec.Port = p
		} else if strings.HasPrefix(spec.Original, "[") && strings.Contains(spec.Original, "]") {
			end := strings.Index(spec.Original, "]")
			spec.Host = spec.Original[1:end]
			rest := spec.Original[end+1:]
			if strings.HasPrefix(rest, ":") {
				spec.Port = strings.TrimPrefix(rest, ":")
			}
		} else if strings.Count(spec.Original, ":") == 1 {
			h, p, ok := strings.Cut(spec.Original, ":")
			if ok && h != "" && p != "" {
				spec.Host = h
				spec.Port = p
			} else {
				spec.Host = spec.Original
			}
		} else {
			spec.Host = spec.Original
		}
	}

	spec.Host = strings.TrimSpace(strings.Trim(spec.Host, "[]"))
	spec.Port = strings.TrimSpace(spec.Port)
	if spec.Host == "" {
		return spec, errors.New("target has empty host")
	}
	if strings.ContainsAny(spec.Host, "/?#") {
		return spec, fmt.Errorf("target host contains invalid characters: %q", spec.Host)
	}
	if spec.Port != "" {
		port, err := strconv.Atoi(spec.Port)
		if err != nil || port < 1 || port > 65535 {
			return spec, fmt.Errorf("invalid target port: %q", spec.Port)
		}
	}
	return spec, nil
}

// ResolveTarget resolves a hostname to an IP address
func ResolveTarget(ctx context.Context, host, family string) string {
	if IsAddressLike(host) {
		return strings.Trim(host, "[]")
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return ""
	}
	for _, addr := range addrs {
		ip := addr.IP
		if family == "4" && ip.To4() == nil {
			continue
		}
		if family == "6" && ip.To4() != nil {
			continue
		}
		return ip.String()
	}
	if len(addrs) > 0 {
		return addrs[0].IP.String()
	}
	return ""
}

// NewTraceResult creates a new TraceResult
func NewTraceResult(spec TargetSpec, resolved string) TraceResult {
	return TraceResult{
		DestinationHost:    spec.Host,
		DestinationPort:    spec.Port,
		DestinationAddress: resolved,
		ResolvedAddress:    resolved,
	}
}

// MergeTraceDestination merges destination info from source to destination
func MergeTraceDestination(dst *TraceResult, src TraceResult) {
	if src.DestinationHost != "" {
		dst.DestinationHost = src.DestinationHost
	}
	if src.DestinationAddress != "" {
		dst.DestinationAddress = src.DestinationAddress
	}
	if src.DestinationPort != "" {
		dst.DestinationPort = src.DestinationPort
	}
	if src.ResolvedAddress != "" {
		dst.ResolvedAddress = src.ResolvedAddress
	}
}
