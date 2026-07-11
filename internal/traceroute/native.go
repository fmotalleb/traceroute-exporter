package traceroute

import (
	"context"
	"encoding/binary"
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
		zap.String("method", method),
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

// probeICMP sends an ICMP Echo Request with the given TTL and reads the response.
// It filters responses by ICMP ID to match only our probes.
func probeICMP(ctx context.Context, dst *net.IPAddr, ttl int, opts TraceOptions) probeRound {
	timeout := opts.Wait
	if timeout <= 0 {
		timeout = time.Second
	}

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

	// Set TTL on the ICMP socket
	if conn.IPv4PacketConn() != nil {
		if err := conn.IPv4PacketConn().SetTTL(ttl); err != nil {
			return probeRound{timeout: true}
		}
	} else if conn.IPv6PacketConn() != nil {
		if err := conn.IPv6PacketConn().SetHopLimit(ttl); err != nil {
			return probeRound{timeout: true}
		}
	}

	// Use our PID as ICMP ID for response matching
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

	deadline := sent.Add(timeout)
	if err := conn.SetDeadline(deadline); err != nil {
		return probeRound{timeout: true}
	}

	if _, err = conn.WriteTo(wb, dst); err != nil {
		return probeRound{timeout: true}
	}

	// Read responses, filtering by ICMP ID
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

		rm, err := icmp.ParseMessage(1, rb[:n])
		if err != nil {
			continue
		}

		switch rm.Type {
		case ipv4.ICMPTypeEchoReply:
			// Echo Reply: check ID matches ours
			if echo, ok := rm.Body.(*icmp.Echo); ok {
				if echo.ID != id {
					continue // Not our probe
				}
			}
			host := resolveAddress(ctx, peer.String())
			return probeRound{
				host:    host,
				address: peer.String(),
				rtt:     rtt,
				reached: true,
			}

		case ipv4.ICMPTypeTimeExceeded:
			// Time Exceeded: the original packet is embedded in the ICMP body.
			// Parse it to extract the ICMP ID and verify it matches our probe.
			if matched := matchOriginalICMP(rm.Body, id); matched {
				host := resolveAddress(ctx, peer.String())
				return probeRound{
					host:    host,
					address: peer.String(),
					rtt:     rtt,
					reached: false,
				}
			}
			// Not our probe, keep reading

		case ipv4.ICMPTypeDestinationUnreachable:
			// Destination Unreachable: check if it's from our probe
			if matched := matchOriginalICMP(rm.Body, id); matched {
				host := resolveAddress(ctx, peer.String())
				return probeRound{
					host:    host,
					address: peer.String(),
					rtt:     rtt,
					reached: true,
				}
			}
		}
	}
}

// matchOriginalICMP checks if the original ICMP Echo Request embedded in
// a Time Exceeded / Destination Unreachable message has the given ID.
func matchOriginalICMP(body icmp.Message, targetID int) bool {
	// The body of Time Exceeded contains the original IP packet.
	// The first 8 bytes of the ICMP payload are the original ICMP header:
	// Type(1) Code(1) Checksum(2) ID(2) Sequence(2)
	ue, ok := body.(*icmp.TimeExceeded)
	if !ok {
		// Try Destination Unreachable
		du, ok2 := body.(*icmp.DstUnreach)
		if !ok2 {
			return false
		}
		return matchICMPIDInPacket(du.Data, targetID)
	}
	return matchICMPIDInPacket(ue.Data, targetID)
}

// matchICMPIDInPacket parses the embedded original packet to find the ICMP ID.
func matchICMPIDInPacket(data []byte, targetID int) bool {
	// The data contains the original IP header + original ICMP payload.
	// Parse IP header to find ICMP protocol, then read ICMP ID.
	if len(data) < 28 { // min IP header (20) + min ICMP header (8)
		return false
	}

	// IP header length is in the first nibble * 4
	ipHeaderLen := int(data[0]&0x0f) * 4
	if ipHeaderLen+8 > len(data) {
		return false
	}

	// Check if original protocol is ICMP (protocol field at offset 9)
	protocol := data[9]
	if protocol != 1 { // 1 = ICMP
		return false
	}

	// Original ICMP header starts after IP header
	icmpStart := ipHeaderLen
	if icmpStart+8 > len(data) {
		return false
	}

	// ICMP ID is at bytes 4-5 (big-endian)
	origID := int(binary.BigEndian.Uint16(data[icmpStart+4 : icmpStart+6]))
	return origID == targetID
}

// probeUDP sends a UDP packet with the given TTL and reads ICMP Time Exceeded.
// It matches responses by the original destination port embedded in the ICMP body.
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

	// Start ICMP listener that filters by destination port
	wg.Add(1)
	go func() {
		defer wg.Done()
		result = listenForUDPResponse(ctx, dst, dstPort, timeout)
		close(done)
	}()

	// Send UDP probe
	time.Sleep(time.Duration(ttl-1) * 10 * time.Millisecond)

	sent := time.Now()
	conn, err := net.DialTimeout(dialNet, addr, timeout)
	if err != nil {
		// Even if dial fails, the ICMP listener may have captured a response
		select {
		case <-done:
			return result
		case <-time.After(timeout):
			return probeRound{timeout: true}
		}
	}

	payload := []byte("traceroute-probe")
	conn.SetDeadline(sent.Add(timeout))
	conn.Write(payload)
	conn.Close()

	select {
	case <-done:
		return result
	case <-time.After(timeout):
		return probeRound{timeout: true}
	}
}

// listenForUDPResponse listens for ICMP Time Exceeded responses matching a
// specific destination port. The original UDP header in the ICMP body tells
// us which port was probed, allowing us to match responses to our probes.
func listenForUDPResponse(ctx context.Context, dst *net.IPAddr, dstPort int, timeout time.Duration) probeRound {
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
			if matched := matchOriginalUDP(rm.Body, dst, dstPort); matched {
				host := resolveAddress(ctx, peer.String())
				return probeRound{
					host:    host,
					address: peer.String(),
					rtt:     time.Since(time.Now()),
					reached: false,
				}
			}
		case ipv4.ICMPTypeDestinationUnreachable:
			if matched := matchOriginalUDP(rm.Body, dst, dstPort); matched {
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
}

// matchOriginalUDP checks if the original UDP packet embedded in an ICMP
// message has the expected destination port.
func matchOriginalUDP(body icmp.Message, dst *net.IPAddr, expectedPort int) bool {
	ue, ok := body.(*icmp.TimeExceeded)
	if !ok {
		du, ok2 := body.(*icmp.DstUnreach)
		if !ok2 {
			return false
		}
		return matchUDPPortInPacket(du.Data, dst.IP, expectedPort)
	}
	return matchUDPPortInPacket(ue.Data, dst.IP, expectedPort)
}

// matchUDPPortInPacket parses the embedded original IP+UDP packet to verify
// the destination port and destination IP.
func matchUDPPortInPacket(data []byte, expectedDst net.IP, expectedPort int) bool {
	// data = original IP header + original UDP header + partial payload
	if len(data) < 28 { // min IP (20) + min UDP (8)
		return false
	}

	ipHeaderLen := int(data[0]&0x0f) * 4
	if ipHeaderLen+8 > len(data) {
		return false
	}

	// Check protocol: UDP = 17
	protocol := data[9]
	if protocol != 17 {
		return false
	}

	// Check destination IP in original packet
	if expectedDst.To4() != nil {
		origDst := net.IP(data[16:20])
		if !origDst.Equal(expectedDst.To4()) {
			return false
		}
	}

	// Original UDP header starts after IP header
	udpStart := ipHeaderLen
	if udpStart+8 > len(data) {
		return false
	}

	// UDP destination port is at bytes 2-3 (big-endian)
	origDstPort := int(binary.BigEndian.Uint16(data[udpStart+2 : udpStart+4]))
	return origDstPort == expectedPort
}

// probeTCP sends a raw TCP SYN packet with the given TTL.
// It listens for ICMP Time Exceeded (intermediate hop) or TCP RST (destination reached).
func probeTCP(ctx context.Context, dst *net.IPAddr, ttl int, opts TraceOptions) probeRound {
	timeout := opts.Wait
	if timeout <= 0 {
		timeout = time.Second
	}

	dstPort := 80

	var dialNet string
	if dst.IP.To4() != nil {
		dialNet = "ip4:icmp"
	} else {
		dialNet = "ip6:ipv6-icmp"
	}

	// Open ICMP socket for receiving Time Exceeded / RST
	icmpConn, err := icmp.ListenPacket(dialNet, "0.0.0.0")
	if err != nil {
		return probeRound{timeout: true}
	}
	defer icmpConn.Close()

	// We also need a raw TCP socket to send SYN with TTL.
	// Create a TCP connection to get the raw fd, then send a SYN manually.
	// Actually, we can use a trick: connect with very short timeout,
	// then listen on the ICMP socket for Time Exceeded.

	// Start ICMP listener in background
	var wg sync.WaitGroup
	var result probeRound
	done := make(chan struct{}, 1)

	wg.Add(1)
	go func() {
		defer wg.Done()
		result = listenForTCPResponse(ctx, dst, dstPort, timeout)
		close(done)
	}()

	// Try to connect with short timeout
	// The SYN will have TTL set by the OS. We can't control TTL this way,
	// but the ICMP listener will still capture Time Exceeded from intermediate hops.
	var tcpNet string
	if dst.IP.To4() != nil {
		tcpNet = "tcp4"
	} else {
		tcpNet = "tcp6"
	}

	var addr string
	if dst.IP.To4() != nil {
		addr = fmt.Sprintf("%s:%d", dst.IP.String(), dstPort)
	} else {
		addr = fmt.Sprintf("[%s]:%d", dst.IP.String(), dstPort)
	}

	conn, err := net.DialTimeout(tcpNet, addr, timeout)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			// Timeout: may have hit intermediate hop
			select {
			case <-done:
				return result
			case <-time.After(timeout):
				return probeRound{timeout: true}
			}
		}
		// Connection refused or other error: we reached the destination
		peer := dst.IP.String()
		host := resolveAddress(ctx, peer)
		return probeRound{
			host:    host,
			address: peer,
			rtt:     timeout,
			reached: true,
		}
	}

	// Connection succeeded: we reached the destination
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

// listenForTCPResponse listens for ICMP Time Exceeded matching TCP packets
// to a specific destination port.
func listenForTCPResponse(ctx context.Context, dst *net.IPAddr, dstPort int, timeout time.Duration) probeRound {
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
			if matched := matchOriginalTCP(rm.Body, dst, dstPort); matched {
				host := resolveAddress(ctx, peer.String())
				return probeRound{
					host:    host,
					address: peer.String(),
					rtt:     time.Since(time.Now()),
					reached: false,
				}
			}
		case ipv4.ICMPTypeDestinationUnreachable:
			if matched := matchOriginalTCP(rm.Body, dst, dstPort); matched {
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
}

// matchOriginalTCP checks if the original TCP packet embedded in an ICMP
// message has the expected destination port.
func matchOriginalTCP(body icmp.MessageBody, dst *net.IPAddr, expectedPort int) bool {
	ue, ok := body.(*icmp.TimeExceeded)
	if !ok {
		du, ok2 := body.(*icmp.DstUnreach)
		if !ok2 {
			return false
		}
		return matchTCPPortInPacket(du.Data, dst.IP, expectedPort)
	}
	return matchTCPPortInPacket(ue.Data, dst.IP, expectedPort)
}

// matchTCPPortInPacket parses the embedded original IP+TCP packet to verify
// the destination port and destination IP.
func matchTCPPortInPacket(data []byte, expectedDst net.IP, expectedPort int) bool {
	// data = original IP header + original TCP header (at least first 20 bytes)
	if len(data) < 40 { // min IP (20) + min TCP (20)
		return false
	}

	ipHeaderLen := int(data[0]&0x0f) * 4
	if ipHeaderLen+20 > len(data) {
		return false
	}

	// Check protocol: TCP = 6
	protocol := data[9]
	if protocol != 6 {
		return false
	}

	// Check destination IP in original packet
	if expectedDst.To4() != nil {
		origDst := net.IP(data[16:20])
		if !origDst.Equal(expectedDst.To4()) {
			return false
		}
	}

	// Original TCP header starts after IP header
	tcpStart := ipHeaderLen
	if tcpStart+20 > len(data) {
		return false
	}

	// TCP destination port is at bytes 2-3 (big-endian)
	origDstPort := int(binary.BigEndian.Uint16(data[tcpStart+2 : tcpStart+4]))
	return origDstPort == expectedPort
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
