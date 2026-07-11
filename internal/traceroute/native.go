package traceroute

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/fmotalleb/go-tools/log"
	"go.uber.org/zap"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// probeRound holds the result for a single probe response
type probeRound struct {
	host    string
	address string
	rtt     time.Duration
	reached bool
	timeout bool
}

// NativeTraceroute performs a traceroute using native Go packet operations
// without depending on the system traceroute binary.
func NativeTraceroute(ctx context.Context, target string, opts TraceOptions) ([]Hop, error) {
	logger := log.FromContext(ctx)

	method := NormalizeMethod(opts.Method)
	if method == "auto" {
		method = "icmp"
	}

	dstAddr, err := net.ResolveIPAddr("ip", target)
	if err != nil {
		logger.Error("failed to resolve target", zap.String("target", target), zap.Error(err))
		return nil, fmt.Errorf("resolve target %q: %w", target, err)
	}
	logger.Debug("resolved target",
		zap.String("target", target),
		zap.String("address", dstAddr.String()),
	)

	hops := make([]Hop, 0, opts.MaxHops)

	for ttl := 1; ttl <= opts.MaxHops; ttl++ {
		if ctx.Err() != nil {
			return hops, ctx.Err()
		}

		hop := Hop{Number: ttl}
		var bestResult *probeRound

		for q := 0; q < opts.Queries; q++ {
			if ctx.Err() != nil {
				return hops, ctx.Err()
			}

			round := probeHop(ctx, dstAddr, ttl, opts, method)
			hop.Nodes = appendHopNode(hop.Nodes, round, ttl)

			if round.host != "" && (bestResult == nil || !bestResult.timeout) {
				bestResult = &round
			}

			// Small delay between probes
			if q < opts.Queries-1 {
				select {
				case <-ctx.Done():
					return hops, ctx.Err()
				case <-time.After(10 * time.Millisecond):
				}
			}
		}

		hop.Stars = countTimeouts(hop.Nodes, opts.Queries)

		if hop.Nodes != nil {
			hops = append(hops, hop)
		}

		// If we reached the destination, stop
		if bestResult != nil && bestResult.reached {
			logger.Debug("destination reached", zap.Int("ttl", ttl))
			break
		}
	}

	return hops, nil
}

// probeHop sends a single probe at the given TTL and waits for a response
func probeHop(ctx context.Context, dst *net.IPAddr, ttl int, opts TraceOptions, method string) probeRound {
	switch method {
	case "icmp":
		return probeICMP(ctx, dst, ttl, opts)
	case "udp":
		return probeUDP(ctx, dst, ttl, opts)
	case "tcp":
		return probeTCP(ctx, dst, ttl, opts)
	default:
		return probeICMP(ctx, dst, ttl, opts)
	}
}

// probeICMP sends an ICMP Echo Request with the given TTL and reads the response
func probeICMP(ctx context.Context, dst *net.IPAddr, ttl int, opts TraceOptions) probeRound {
	timeout := opts.Wait
	if timeout <= 0 {
		timeout = time.Second
	}

	// Determine IP version
	var network string
	if dst.IP.To4() != nil {
		network = "ip4:icmp"
	} else {
		network = "ip6:ipv6-icmp"
	}

	conn, err := icmp.ListenPacket(network, "0.0.0.0")
	if err != nil {
		return probeRound{timeout: true}
	}
	defer conn.Close()

	// Set TTL
	if conn.IPv4PacketConn() != nil {
		if err := conn.IPv4PacketConn().SetTTL(ttl); err != nil {
			return probeRound{timeout: true}
		}
	} else if conn.IPv6PacketConn() != nil {
		if err := conn.IPv6PacketConn().SetHopLimit(ttl); err != nil {
			return probeRound{timeout: true}
		}
	}

	// Build ICMP Echo Request
	id := os.Getpid() & 0xffff
	seq := ttl
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   id,
			Seq:  seq,
			Data: []byte("traceroute-probe"),
		},
	}

	wb, err := msg.Marshal(nil)
	if err != nil {
		return probeRound{timeout: true}
	}

	sent := time.Now()

	// Set deadline
	deadline := sent.Add(timeout)
	if err := conn.SetDeadline(deadline); err != nil {
		return probeRound{timeout: true}
	}

	_, err = conn.WriteTo(wb, dst)
	if err != nil {
		return probeRound{timeout: true}
	}

	// Read response
	rb := make([]byte, 1500)
	for {
		n, peer, err := conn.ReadFrom(rb)
		if err != nil {
			if os.IsTimeout(err) || ctx.Err() != nil {
				return probeRound{timeout: true}
			}
			return probeRound{timeout: true}
		}

		rtt := time.Since(sent)

		rm, err := icmp.ParseMessage(1, rb[:n]) // protocol 1 = ICMP
		if err != nil {
			continue
		}

		switch rm.Type {
		case ipv4.ICMPTypeEchoReply:
			// We reached the destination
			host := resolveAddress(ctx, peer.String())
			return probeRound{
				host:    host,
				address: peer.String(),
				rtt:     rtt,
				reached: true,
			}
		case ipv4.ICMPTypeTimeExceeded:
			// Intermediate hop
			host := resolveAddress(ctx, peer.String())
			return probeRound{
				host:    host,
				address: peer.String(),
				rtt:     rtt,
				reached: false,
			}
		case ipv4.ICMPTypeDestinationUnreachable:
			host := resolveAddress(ctx, peer.String())
			return probeRound{
				host:    host,
				address: peer.String(),
				rtt:     rtt,
				reached: true, // Unreachable from destination means we reached it
			}
		}
	}
}

// probeUDP sends a UDP packet with the given TTL and reads ICMP Time Exceeded
func probeUDP(ctx context.Context, dst *net.IPAddr, ttl int, opts TraceOptions) probeRound {
	timeout := opts.Wait
	if timeout <= 0 {
		timeout = time.Second
	}

	dstPort := 33434 + ttl

	var dialNet string
	if dst.IP.To4() != nil {
		dialNet = "udp4"
	} else {
		dialNet = "udp6"
	}

	var addr string
	if dst.IP.To4() != nil {
		addr = fmt.Sprintf("%s:%d", dst.IP.String(), dstPort)
	} else {
		addr = fmt.Sprintf("[%s]:%d", dst.IP.String(), dstPort)
	}

	var wg sync.WaitGroup
	var result probeRound
	done := make(chan struct{}, 1)

	// Start ICMP listener in background
	wg.Add(1)
	go func() {
		defer wg.Done()
		result = listenForICMPResponse(ctx, dst, timeout)
		close(done)
	}()

	// Send UDP probe
	time.Sleep(time.Duration(ttl-1) * 10 * time.Millisecond) // Stagger by TTL

	sent := time.Now()
	conn, err := net.DialTimeout(dialNet, addr, timeout)
	if err != nil {
		// Even if dial fails (port unreachable), we may get ICMP Time Exceeded
		<-done
		return result
	}

	payload := []byte("traceroute-probe")
	conn.SetDeadline(sent.Add(timeout))
	conn.Write(payload)
	conn.Close()

	// Wait for ICMP response or timeout
	select {
	case <-done:
		return result
	case <-time.After(timeout):
		return probeRound{timeout: true}
	}
}

// probeTCP performs a TCP traceroute using a raw socket approach.
// It attempts to connect to the target and interprets the response
// to determine if we've reached the destination or an intermediate hop.
func probeTCP(ctx context.Context, dst *net.IPAddr, ttl int, opts TraceOptions) probeRound {
	timeout := opts.Wait
	if timeout <= 0 {
		timeout = time.Second
	}

	var dialNet string
	if dst.IP.To4() != nil {
		dialNet = "tcp4"
	} else {
		dialNet = "tcp6"
	}

	dstPort := 80

	var addr string
	if dst.IP.To4() != nil {
		addr = fmt.Sprintf("%s:%d", dst.IP.String(), dstPort)
	} else {
		addr = fmt.Sprintf("[%s]:%d", dst.IP.String(), dstPort)
	}

	conn, err := net.DialTimeout(dialNet, addr, timeout)
	if err != nil {
		// Check if it's a timeout (hop not reached) or connection refused (destination)
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return probeRound{timeout: true}
		}
		// Connection refused often means we reached the destination
		peer := dst.IP.String()
		host := resolveAddress(ctx, peer)
		return probeRound{
			host:    host,
			address: peer,
			rtt:     timeout,
			reached: true,
		}
	}

	// Connection succeeded - we reached the destination
	peer := conn.RemoteAddr().String()
	host := resolveAddress(ctx, peer)
	conn.Close()

	return probeRound{
		host:    host,
		address: peer,
		rtt:     time.Since(time.Now()),
		reached: true,
	}
}

// listenForICMPResponse listens for ICMP Time Exceeded responses
func listenForICMPResponse(ctx context.Context, dst *net.IPAddr, timeout time.Duration) probeRound {
	var network string
	if dst.IP.To4() != nil {
		network = "ip4:icmp"
	} else {
		network = "ip6:ipv6-icmp"
	}

	conn, err := icmp.ListenPacket(network, "0.0.0.0")
	if err != nil {
		return probeRound{timeout: true}
	}
	defer conn.Close()

	deadline := time.Now().Add(timeout)
	conn.SetDeadline(deadline)

	rb := make([]byte, 1500)
	for {
		n, peer, err := conn.ReadFrom(rb)
		if err != nil {
			return probeRound{timeout: true}
		}

		rm, err := icmp.ParseMessage(1, rb[:n])
		if err != nil {
			continue
		}

		switch rm.Type {
		case ipv4.ICMPTypeTimeExceeded:
			host := resolveAddress(ctx, peer.String())
			return probeRound{
				host:    host,
				address: peer.String(),
				rtt:     time.Since(time.Now()),
				reached: false,
			}
		case ipv4.ICMPTypeDestinationUnreachable:
			host := resolveAddress(ctx, peer.String())
			return probeRound{
				host:    host,
				address: peer.String(),
				rtt:     time.Since(time.Now()),
				reached: true,
			}
		}
	}
}

// resolveAddress tries to resolve an IP address to a hostname
func resolveAddress(ctx context.Context, addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}

	names, err := net.LookupAddr(host)
	if err != nil || len(names) == 0 {
		return host
	}
	return names[0]
}

// appendHopNode adds a probe result to the hop's node list
func appendHopNode(nodes []*Node, round probeRound, ttl int) []*Node {
	if round.host == "" && round.address == "" {
		return nodes
	}

	id := round.address
	if id == "" {
		id = round.host
	}
	if id == "" {
		id = fmt.Sprintf("no-reply-hop-%02d", ttl)
	}

	// Check if this node already exists
	for _, n := range nodes {
		if n.ID == id {
			if !round.timeout {
				n.RTTs = append(n.RTTs, round.rtt.Seconds())
			}
			return nodes
		}
	}

	hostname := round.host
	if hostname == "" {
		hostname = id
	}

	node := &Node{
		ID:        id,
		Hop:       ttl,
		Hostname:  hostname,
		Address:   round.address,
		Responded: !round.timeout,
		Role:      "hop",
	}

	if !round.timeout {
		node.RTTs = []float64{round.rtt.Seconds()}
	}

	return append(nodes, node)
}

// countTimeouts counts the number of timeouts in a query set
func countTimeouts(nodes []*Node, queries int) int {
	responded := 0
	for _, n := range nodes {
		if n.Responded {
			responded++
		}
	}
	return queries - responded
}
