package cluster

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"

	"github.com/jdpanderson/cheesecloth/enroll"
	"github.com/jdpanderson/cheesecloth/trust"
	"github.com/quic-go/quic-go"
)

// Enrol runs the joiner's side of enrolment against the member at addr (its
// gossip ip:port) over a QUIC stream from a throwaway socket.
func Enrol(ctx context.Context, addr, token string, id *trust.Identity, name string) (*enroll.Welcome, error) {
	cert, err := identityCertificate(id)
	if err != nil {
		return nil, err
	}
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: wildcardFor(ua.IP)})
	if err != nil {
		return nil, err
	}
	qt := &quic.Transport{Conn: udp}
	defer func() { _ = qt.Close(); _ = udp.Close() }()

	tlsConf := enrolTLSConfig(cert)
	tlsConf.ClientAuth = tls.NoClientCert
	conn, err := qt.Dial(ctx, ua, tlsConf, &quic.Config{HandshakeIdleTimeout: handshakeTime})
	if err != nil {
		return nil, fmt.Errorf("connecting to %s: %w", addr, err)
	}
	defer func() { _ = conn.CloseWithError(0, "done") }()
	if conn.ConnectionState().TLS.NegotiatedProtocol != alpnEnrol {
		return nil, fmt.Errorf("%s does not offer enrolment", addr)
	}
	s, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	stream := newStreamConn(conn, s, peerOf(conn))
	defer func() { _ = stream.Close() }()
	return enroll.Join(stream, token, id, name)
}

// wildcardFor is the unspecified address of ip's family.
func wildcardFor(ip net.IP) net.IP {
	if ip.To4() != nil {
		return net.IPv4zero
	}
	return net.IPv6unspecified
}
