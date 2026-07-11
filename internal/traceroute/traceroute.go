package traceroute

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os/exec"
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

// ProbeTrace executes a traceroute probe
func ProbeTrace(ctx context.Context, traceroutePath string, spec TargetSpec, opts TraceOptions, resolved string) (CommandResult, TraceResult, error) {
	if opts.LoopMaxRepeats > 0 {
		return runTracerouteIncremental(ctx, traceroutePath, spec, opts, resolved)
	}
	return runTracerouteFull(ctx, traceroutePath, spec, opts, resolved)
}

func runTracerouteFull(ctx context.Context, traceroutePath string, spec TargetSpec, opts TraceOptions, resolved string) (CommandResult, TraceResult, error) {
	logger := log.FromContext(ctx)
	trace := NewTraceResult(spec, resolved)
	args, err := BuildTracerouteArgs(spec, opts, 1, opts.MaxHops)
	if err != nil {
		logger.Error("failed to build traceroute args", zap.Error(err))
		return CommandResult{Args: args, ExitCode: -1, Err: err}, trace, err
	}

	cmdResult, err := execTraceroute(ctx, traceroutePath, args)
	trace = ParseTraceOutput(cmdResult.Output, spec, resolved, opts.Queries)
	trace.RawOutput = cmdResult.Output
	trace.Loop = DetectLoop(trace.Hops, opts.LoopMaxRepeats)
	if trace.Loop.GiveUp {
		trace.Hops = TrimHopsAfter(trace.Hops, trace.Loop.EndHop)
	}
	return cmdResult, trace, err
}

func runTracerouteIncremental(ctx context.Context, traceroutePath string, spec TargetSpec, opts TraceOptions, resolved string) (CommandResult, TraceResult, error) {
	logger := log.FromContext(ctx)
	started := time.Now()
	trace := NewTraceResult(spec, resolved)
	aggregate := CommandResult{ExitCode: 0}
	var outputParts []string

	finish := func(err error) (CommandResult, TraceResult, error) {
		aggregate.Output = strings.Join(outputParts, "\n")
		aggregate.Duration = time.Since(started)
		aggregate.Err = err
		if err != nil && aggregate.ExitCode == 0 {
			aggregate.ExitCode = -1
		}
		return aggregate, trace, err
	}

	for hop := 1; hop <= opts.MaxHops; hop++ {
		if ctx.Err() != nil {
			aggregate.TimedOut = true
			aggregate.ExitCode = -2
			return finish(ctx.Err())
		}

		args, err := BuildTracerouteArgs(spec, opts, hop, hop)
		if err != nil {
			aggregate.Args = args
			aggregate.ExitCode = -1
			return finish(err)
		}

		cmdResult, err := execTraceroute(ctx, traceroutePath, args)
		aggregate.Args = cmdResult.Args
		aggregate.Commands = append(aggregate.Commands, cmdResult.Commands...)
		if strings.TrimSpace(cmdResult.Output) != "" {
			outputParts = append(outputParts, cmdResult.Output)
		}

		if cmdResult.TimedOut || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			aggregate.TimedOut = true
			aggregate.ExitCode = -2
			return finish(ctx.Err())
		}

		hopTrace := ParseTraceOutput(cmdResult.Output, spec, resolved, opts.Queries)
		MergeTraceDestination(&trace, hopTrace)
		addedHop := false
		for _, parsedHop := range hopTrace.Hops {
			if parsedHop.Number == hop {
				trace.Hops = append(trace.Hops, parsedHop)
				addedHop = true
			}
		}

		if err != nil && !addedHop {
			aggregate.ExitCode = cmdResult.ExitCode
			return finish(err)
		}

		trace.Loop = DetectLoop(trace.Hops, opts.LoopMaxRepeats)
		if trace.Loop.GiveUp {
			return finish(nil)
		}
		if ComputeReached(trace, spec) {
			return finish(nil)
		}
	}

	logger.Debug("traceroute completed", zap.Int("total_hops", len(trace.Hops)))
	return finish(nil)
}

func execTraceroute(ctx context.Context, traceroutePath string, args []string) (CommandResult, error) {
	logger := log.FromContext(ctx)
	command := strings.Join(append([]string{traceroutePath}, args...), " ")
	result := CommandResult{Args: args, Commands: []string{command}, ExitCode: 0}

	logger.Debug("executing traceroute", zap.String("command", command))

	cmd := exec.CommandContext(ctx, traceroutePath, args...)
	started := time.Now()
	out, err := cmd.CombinedOutput()
	result.Duration = time.Since(started)
	result.Output = string(out)

	if ctx.Err() == context.DeadlineExceeded {
		result.TimedOut = true
		result.ExitCode = -2
		result.Err = ctx.Err()
		return result, ctx.Err()
	}
	if err != nil {
		result.Err = err
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			result.ExitCode = exitErr.ExitCode()
		} else {
			result.ExitCode = -1
		}
		return result, err
	}
	return result, nil
}

// BuildTracerouteArgs constructs command-line arguments for traceroute
func BuildTracerouteArgs(spec TargetSpec, opts TraceOptions, firstHop, maxHop int) ([]string, error) {
	method := NormalizeMethod(opts.Method)
	if method == "auto" {
		if spec.Port != "" {
			method = "tcp"
		} else {
			method = "icmp"
		}
	}
	if maxHop <= 0 {
		maxHop = opts.MaxHops
	}
	if firstHop <= 0 {
		firstHop = 1
	}

	args := []string{
		"-m", strconv.Itoa(maxHop),
		"-q", strconv.Itoa(opts.Queries),
		"-w", SecondsForTraceroute(opts.Wait),
	}
	if firstHop > 1 {
		args = append(args, "-f", strconv.Itoa(firstHop))
	}

	switch NormalizeIPFamily(opts.IPFamily) {
	case "4":
		args = append(args, "-4")
	case "6":
		args = append(args, "-6")
	}

	switch method {
	case "tcp":
		args = append(args, "-T")
		if spec.Port != "" {
			args = append(args, "-p", spec.Port)
		}
	case "icmp":
		args = append(args, "-I")
	case "udp":
		if spec.Port != "" {
			args = append(args, "-p", spec.Port)
		}
	default:
		return nil, fmt.Errorf("unsupported traceroute method %q", opts.Method)
	}

	args = append(args, spec.Host)
	return args, nil
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
