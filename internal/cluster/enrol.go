package cluster

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/jdpanderson/cheesecloth/internal/enrol"
	"github.com/jdpanderson/cheesecloth/internal/trust"
	"github.com/quic-go/quic-go"
)

// Enrol runs the joiner's side of enrolment against the member at addr (its
// gossip ip:port) over a QUIC stream from a throwaway socket, and returns the
// welcome and the member's identity.
func Enrol(ctx context.Context, addr, token string, id *trust.Identity, name string) (*enrol.Welcome, trust.PublicKey, error) {
	var none trust.PublicKey
	cert, err := identityCertificate(id)
	if err != nil {
		return nil, none, err
	}
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, none, err
	}
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: wildcardFor(ua.IP)})
	if err != nil {
		return nil, none, err
	}
	qt := &quic.Transport{Conn: udp}
	defer func() { _ = qt.Close(); _ = udp.Close() }()

	conn, err := qt.Dial(ctx, ua, enrolClientTLSConfig(cert), &quic.Config{HandshakeIdleTimeout: handshakeTime})
	if err != nil {
		return nil, none, fmt.Errorf("connecting to %s: %w", addr, err)
	}
	defer func() { _ = conn.CloseWithError(0, "done") }()
	if conn.ConnectionState().TLS.NegotiatedProtocol != alpnEnrol {
		return nil, none, fmt.Errorf("%s does not offer enrolment", addr)
	}
	s, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, none, err
	}
	stream := newStreamConn(conn, s, peerOf(conn))
	defer func() { _ = stream.Close() }()
	w, member, err := enrol.Join(stream, token, id, name)
	if err != nil {
		return nil, none, err
	}
	// The member closes the connection once it has our acknowledgement;
	// closing from this side first could discard the acknowledgement unsent.
	select {
	case <-conn.Context().Done():
	case <-ctx.Done():
	case <-time.After(handshakeTime):
	}
	return w, member, nil
}

// wildcardFor is the unspecified address of ip's family.
func wildcardFor(ip net.IP) net.IP {
	if ip.To4() != nil {
		return net.IPv4zero
	}
	return net.IPv6unspecified
}
