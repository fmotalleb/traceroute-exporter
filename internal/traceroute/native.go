package traceroute

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/fmotalleb/go-tools/log"
	"go.uber.org/zap"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// Constants for native traceroute packet operations.
const (
	bufSize        = 1500
	probePayload   = "traceroute-probe"
	defaultTCPPort = 80
	udpBasePort    = 33434

	// IP/TCP header constants.
	ipHeaderLen   = 20
	tcpHeaderLen  = 20
	tcpTotalLen   = 40
	dummySrcPort  = 12345
	tcpWindowSize = 65535
	pseudoHdrBase = 12
	ipVersionIHL  = 0x45
	tcpDataOffset = 0x50
	tcpFlagsSYN   = 0x02

	// Protocol numbers.
	protoICMP = 1
	protoTCP  = 6
	protoUDP  = 17

	// ICMP embedded packet minimum sizes.
	minICMPDataLen = 28
	minTCPDataLen  = 40

	idMask     = 0xffff
	probeDelay = 10 // milliseconds between probes
)

// probeRound holds the result for a single probe response.
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
	if method == methodAuto {
		method = methodICMP
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

			if q < opts.Queries-1 {
				select {
				case <-ctx.Done():
					return hops, ctx.Err()
				case <-time.After(probeDelay * time.Millisecond):
				}
			}
		}

		hop.Stars = countTimeouts(hop.Nodes, opts.Queries)

		if hop.Nodes != nil {
			hops = append(hops, hop)
		}

		if bestResult != nil && bestResult.reached {
			logger.Debug("destination reached", zap.Int("ttl", ttl))
			break
		}
	}

	return hops, nil
}

// probeHop sends a single probe at the given TTL and waits for a response.
func probeHop(ctx context.Context, dst *net.IPAddr, ttl int, opts TraceOptions, method string) probeRound {
	switch method {
	case methodICMP:
		return probeICMP(ctx, dst, ttl, opts)
	case methodUDP:
		return probeUDP(ctx, dst, ttl, opts)
	case methodTCP:
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

	if conn.IPv4PacketConn() != nil {
		if ttlErr := conn.IPv4PacketConn().SetTTL(ttl); ttlErr != nil {
			return probeRound{timeout: true}
		}
	} else if conn.IPv6PacketConn() != nil {
		if hopErr := conn.IPv6PacketConn().SetHopLimit(ttl); hopErr != nil {
			return probeRound{timeout: true}
		}
	}

	id := os.Getpid() & idMask
	seq := ttl

	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Body: &icmp.Echo{
			ID:   id,
			Seq:  seq,
			Data: []byte(probePayload),
		},
	}

	wb, err := msg.Marshal(nil)
	if err != nil {
		return probeRound{timeout: true}
	}

	sent := time.Now()
	if deadlineErr := conn.SetDeadline(sent.Add(timeout)); deadlineErr != nil {
		return probeRound{timeout: true}
	}

	if _, err := conn.WriteTo(wb, dst); err != nil {
		return probeRound{timeout: true}
	}

	rb := make([]byte, bufSize)
	for {
		n, peer, err := conn.ReadFrom(rb)
		if err != nil {
			return probeRound{timeout: true}
		}

		rtt := time.Since(sent)
		rm, parseErr := icmp.ParseMessage(1, rb[:n])
		if parseErr != nil {
			continue
		}

		switch rm.Type {
		case ipv4.ICMPTypeEchoReply:
			if echo, ok := rm.Body.(*icmp.Echo); ok && echo.ID != id {
				continue
			}
			host := resolveAddress(ctx, peer.String())
			return probeRound{host: host, address: peer.String(), rtt: rtt, reached: true}

		case ipv4.ICMPTypeTimeExceeded:
			if matchOriginalICMP(rm.Body, id) {
				host := resolveAddress(ctx, peer.String())
				return probeRound{host: host, address: peer.String(), rtt: rtt, reached: false}
			}

		case ipv4.ICMPTypeDestinationUnreachable:
			if matchOriginalICMP(rm.Body, id) {
				host := resolveAddress(ctx, peer.String())
				return probeRound{host: host, address: peer.String(), rtt: rtt, reached: true}
			}
		}
	}
}

// probeUDP sends a raw UDP packet with the given TTL and reads ICMP Time Exceeded.
// It uses a raw UDP socket via ipv4.PacketConn to set TTL on outgoing packets.
func probeUDP(ctx context.Context, dst *net.IPAddr, ttl int, opts TraceOptions) probeRound {
	timeout := opts.Wait
	if timeout <= 0 {
		timeout = time.Second
	}

	dstPort := udpBasePort + ttl

	// Create a raw UDP socket to control TTL
	lc := net.ListenConfig{}
	pc, err := lc.ListenPacket(ctx, "udp4", ":0")
	if err != nil {
		return probeRound{timeout: true}
	}
	defer pc.Close()

	// Wrap with ipv4.PacketConn to set TTL
	ippc := ipv4.NewPacketConn(pc)
	if err := ippc.SetTTL(ttl); err != nil {
		return probeRound{timeout: true}
	}

	dstUDP := &net.UDPAddr{IP: dst.IP, Port: dstPort}
	payload := []byte(probePayload)

	// Start ICMP listener in background
	var wg sync.WaitGroup
	var result probeRound
	done := make(chan struct{}, 1)

	wg.Add(1)
	go func() {
		defer wg.Done()
		result = listenForUDPResponse(ctx, dst, dstPort, timeout)
		close(done)
	}()

	// Small stagger before sending
	time.Sleep(time.Duration(ttl-1) * probeDelay * time.Millisecond)

	sent := time.Now()
	if err := pc.SetDeadline(sent.Add(timeout)); err != nil {
		return probeRound{timeout: true}
	}

	// Send the raw UDP packet with TTL set
	if _, err := pc.WriteTo(payload, dstUDP); err != nil {
		// May still get ICMP response
		select {
		case <-done:
			return result
		case <-time.After(timeout):
			return probeRound{timeout: true}
		}
	}

	select {
	case <-done:
		return result
	case <-time.After(timeout):
		return probeRound{timeout: true}
	}
}

// matchFunc is a function that checks if an ICMP message body matches the expected probe.
type matchFunc func(body icmp.MessageBody) bool

// listenForICMPResponse listens for ICMP Time Exceeded or Destination Unreachable
// matching a specific probe (UDP or TCP) using the provided matcher function.
func listenForICMPResponse(ctx context.Context, timeout time.Duration, matcher matchFunc) probeRound {
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return probeRound{timeout: true}
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return probeRound{timeout: true}
	}

	rb := make([]byte, bufSize)
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
			if matcher(rm.Body) {
				host := resolveAddress(ctx, peer.String())
				return probeRound{host: host, address: peer.String(), rtt: time.Since(time.Now()), reached: false}
			}
		case ipv4.ICMPTypeDestinationUnreachable:
			if matcher(rm.Body) {
				host := resolveAddress(ctx, peer.String())
				return probeRound{host: host, address: peer.String(), rtt: time.Since(time.Now()), reached: true}
			}
		}
	}
}

// listenForUDPResponse listens for ICMP Time Exceeded matching a specific UDP port.
func listenForUDPResponse(ctx context.Context, dst *net.IPAddr, dstPort int, timeout time.Duration) probeRound {
	return listenForICMPResponse(ctx, timeout, func(body icmp.MessageBody) bool {
		return matchOriginalUDP(body, dst, dstPort)
	})
}

// probeTCP sends a raw TCP SYN packet with the given TTL and listens for
// ICMP Time Exceeded (intermediate hop) or TCP RST (destination reached).
// Requires CAP_NET_RAW or root for raw socket access.
func probeTCP(ctx context.Context, dst *net.IPAddr, ttl int, opts TraceOptions) probeRound {
	timeout := opts.Wait
	if timeout <= 0 {
		timeout = time.Second
	}

	dstPort := defaultTCPPort

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

	// Send raw TCP SYN with TTL
	sent := time.Now()
	err := sendRawTCPSYN(dst.IP, dstPort, ttl, sent.Add(timeout))
	if err != nil {
		// Raw socket failed (no CAP_NET_RAW). Fall back to regular connect.
		// This won't show intermediate hops but at least shows the destination.
		return probeTCPFallback(ctx, dst, dstPort, timeout)
	}

	// Wait for ICMP response or timeout
	select {
	case <-done:
		return result
	case <-time.After(timeout):
		return probeRound{timeout: true}
	}
}

// sendRawTCPSYN sends a raw TCP SYN packet with the given TTL.
func sendRawTCPSYN(dstIP net.IP, dstPort, ttl int, _ time.Time) error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return fmt.Errorf("raw socket: %w", err)
	}
	defer syscall.Close(fd)

	// Tell kernel we're providing the IP header
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		return fmt.Errorf("setsockopt IP_HDRINCL: %w", err)
	}

	// Set TTL
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_TTL, ttl); err != nil {
		return fmt.Errorf("setsockopt IP_TTL: %w", err)
	}

	// Build IP header (20 bytes)
	srcIP := net.IPv4(0, 0, 0, 0).To4()
	ipHeader := make([]byte, ipHeaderLen)
	ipHeader[0] = ipVersionIHL                             // version=4, IHL=5
	ipHeader[1] = 0                                        // DSCP/ECN
	binary.BigEndian.PutUint16(ipHeader[2:4], tcpTotalLen) // total length: 20+20
	ipHeader[8] = byte(ttl)                                // TTL
	ipHeader[9] = protoTCP                                 // protocol: TCP
	copy(ipHeader[12:16], srcIP)
	copy(ipHeader[16:20], dstIP.To4())

	// Build TCP header (20 bytes, SYN only)
	tcpHeader := make([]byte, tcpHeaderLen)
	binary.BigEndian.PutUint16(tcpHeader[0:2], dummySrcPort)    // source port
	binary.BigEndian.PutUint16(tcpHeader[2:4], uint16(dstPort)) // dest port
	tcpHeader[12] = tcpDataOffset                               // data offset: 5 (20 bytes)
	tcpHeader[13] = tcpFlagsSYN                                 // flags: SYN
	binary.BigEndian.PutUint16(tcpHeader[14:16], tcpWindowSize) // window

	// Calculate TCP checksum
	tcpLen := tcpHeaderLen
	pseudo := make([]byte, pseudoHdrBase+tcpLen)
	copy(pseudo[0:4], srcIP)
	copy(pseudo[4:8], dstIP.To4())
	pseudo[8] = 0
	pseudo[9] = protoTCP // TCP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(tcpLen))
	copy(pseudo[12:], tcpHeader)
	tcpHeader[16] = 0
	tcpHeader[17] = 0
	csum := tcpChecksum(pseudo)
	binary.BigEndian.PutUint16(tcpHeader[16:18], csum)

	// IP checksum
	ipHeader[10] = 0
	ipHeader[11] = 0
	ipCsum := ipv4Checksum(ipHeader)
	binary.BigEndian.PutUint16(ipHeader[10:12], ipCsum)

	packet := make([]byte, 0, len(ipHeader)+len(tcpHeader))
	packet = append(packet, ipHeader...)
	packet = append(packet, tcpHeader...)

	addr := syscall.SockaddrInet4{Port: dstPort}
	copy(addr.Addr[:], dstIP.To4())

	return syscall.Sendto(fd, packet, 0, &addr)
}

// tcpChecksum computes the TCP checksum including the pseudo-header.
func tcpChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i:]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// ipv4Checksum computes the IPv4 header checksum.
func ipv4Checksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i:]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// probeTCPFallback is used when raw sockets aren't available (no CAP_NET_RAW).
// It does a regular TCP connect which can only show the destination, not intermediate hops.
func probeTCPFallback(ctx context.Context, dst *net.IPAddr, dstPort int, timeout time.Duration) probeRound {
	addr := net.JoinHostPort(dst.IP.String(), strconv.Itoa(dstPort))

	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp4", addr)
	if err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return probeRound{timeout: true}
		}
		// Connection refused or other non-timeout net errors = destination reached
		peer := dst.IP.String()
		host := resolveAddress(ctx, peer)
		return probeRound{host: host, address: peer, rtt: timeout, reached: true}
	}

	peer := conn.RemoteAddr().String()
	host := resolveAddress(ctx, peer)
	_ = conn.Close() // ignore close error
	return probeRound{host: host, address: peer, rtt: time.Since(time.Now()), reached: true}
}

// listenForTCPResponse listens for ICMP Time Exceeded matching TCP packets to a specific port.
func listenForTCPResponse(ctx context.Context, dst *net.IPAddr, dstPort int, timeout time.Duration) probeRound {
	return listenForICMPResponse(ctx, timeout, func(body icmp.MessageBody) bool {
		return matchOriginalTCP(body, dst, dstPort)
	})
}

// matchOriginalICMP checks if the original ICMP Echo Request embedded in
// a Time Exceeded / Destination Unreachable message has the given ID.
func matchOriginalICMP(body icmp.MessageBody, targetID int) bool {
	ue, ok := body.(*icmp.TimeExceeded)
	if !ok {
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
	if len(data) < minICMPDataLen {
		return false
	}
	ipHeaderLen := int(data[0]&0x0f) * 4
	if ipHeaderLen+8 > len(data) {
		return false
	}
	protocol := data[9]
	if protocol != protoICMP {
		return false
	}
	icmpStart := ipHeaderLen
	if icmpStart+8 > len(data) {
		return false
	}
	origID := int(binary.BigEndian.Uint16(data[icmpStart+4 : icmpStart+6]))
	return origID == targetID
}

// matchOriginalUDP checks if the original UDP packet embedded in an ICMP
// message has the expected destination port.
func matchOriginalUDP(body icmp.MessageBody, dst *net.IPAddr, expectedPort int) bool {
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

// matchUDPPortInPacket parses the embedded original IP+UDP packet.
func matchUDPPortInPacket(data []byte, expectedDst net.IP, expectedPort int) bool {
	if len(data) < minICMPDataLen {
		return false
	}
	ipHeaderLen := int(data[0]&0x0f) * 4
	if ipHeaderLen+8 > len(data) {
		return false
	}
	protocol := data[9]
	if protocol != protoUDP {
		return false
	}
	if expectedDst.To4() != nil {
		origDst := net.IP(data[16:20])
		if !origDst.Equal(expectedDst.To4()) {
			return false
		}
	}
	udpStart := ipHeaderLen
	if udpStart+8 > len(data) {
		return false
	}
	origDstPort := int(binary.BigEndian.Uint16(data[udpStart+2 : udpStart+4]))
	return origDstPort == expectedPort
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

// matchTCPPortInPacket parses the embedded original IP+TCP packet.
func matchTCPPortInPacket(data []byte, expectedDst net.IP, expectedPort int) bool {
	if len(data) < minTCPDataLen {
		return false
	}
	ipHeaderLen := int(data[0]&0x0f) * 4
	if ipHeaderLen+20 > len(data) {
		return false
	}
	protocol := data[9]
	if protocol != protoTCP {
		return false
	}
	if expectedDst.To4() != nil {
		origDst := net.IP(data[16:20])
		if !origDst.Equal(expectedDst.To4()) {
			return false
		}
	}
	tcpStart := ipHeaderLen
	if tcpStart+20 > len(data) {
		return false
	}
	origDstPort := int(binary.BigEndian.Uint16(data[tcpStart+2 : tcpStart+4]))
	return origDstPort == expectedPort
}

// resolveAddress tries to resolve an IP address to a hostname.
func resolveAddress(ctx context.Context, addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	names, err := net.DefaultResolver.LookupAddr(ctx, host)
	if err != nil || len(names) == 0 {
		return host
	}
	return names[0]
}

// appendHopNode adds a probe result to the hop's node list.
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
		Role:      nodeRoleHop,
	}
	if !round.timeout {
		node.RTTs = []float64{round.rtt.Seconds()}
	}
	return append(nodes, node)
}

// countTimeouts counts the number of timeouts in a query set.
func countTimeouts(nodes []*Node, queries int) int {
	responded := 0
	for _, n := range nodes {
		if n.Responded {
			responded++
		}
	}
	return queries - responded
}
