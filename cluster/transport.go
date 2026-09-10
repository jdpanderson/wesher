package cluster

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/hashicorp/memberlist"
	"github.com/jdpanderson/cheesecloth/trust"
	"github.com/quic-go/quic-go"
)

// The gossip transport runs memberlist over QUIC: one UDP port, one TLS 1.3
// session per pair of nodes, authenticated on both sides by self-signed
// certificates carrying the nodes' identity keys and accepted only for valid
// members. memberlist packets travel as QUIC datagrams (RFC 9221), its
// push/pull exchanges as streams. There is no cluster-wide key.

const (
	alpnGossip    = "cheesecloth-gossip/1"
	identityLen   = 32
	handshakeTime = 10 * time.Second
	idleTimeout   = time.Minute
	keepAlive     = 15 * time.Second
	// maxDatagram bounds memberlist's packets: QUIC guarantees room for at
	// least ~1200 bytes of datagram payload on any path.
	maxDatagram = 1100
)

type quicTransport struct {
	id      *trust.Identity
	set     *trust.Set
	udp     *net.UDPConn
	qt      *quic.Transport
	ln      *quic.Listener
	server  *tls.Config
	client  *tls.Config
	qconf   *quic.Config
	packets chan *memberlist.Packet
	streams chan net.Conn
	done    chan struct{}
	wg      sync.WaitGroup
	once    sync.Once
	err     error        // from Shutdown
	life    sync.RWMutex // held for writing while Shutdown closes the QUIC transport

	mu      sync.Mutex
	conns   map[string]*quic.Conn // by the peer's gossip address
	dialing map[string]bool
}

var _ memberlist.NodeAwareTransport = (*quicTransport)(nil)

// newQUICTransport binds bind:port for QUIC and starts accepting member connections.
func newQUICTransport(bind netip.Addr, port int, id *trust.Identity, set *trust.Set) (*quicTransport, error) {
	cert, err := identityCertificate(id)
	if err != nil {
		return nil, err
	}
	verify := func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		peer, cerr := certIdentity(rawCerts)
		if cerr != nil {
			return cerr
		}
		if !set.Valid(peer) {
			return fmt.Errorf("peer %s is not a member", peer.Short())
		}
		return nil
	}
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: bind.AsSlice(), Port: port})
	if err != nil {
		return nil, fmt.Errorf("binding gossip transport: %w", err)
	}
	var resetKey quic.StatelessResetKey
	if _, err = rand.Read(resetKey[:]); err != nil {
		_ = udp.Close()
		return nil, err
	}
	t := &quicTransport{
		id: id, set: set, udp: udp,
		qt: &quic.Transport{Conn: udp, StatelessResetKey: &resetKey},
		server: &tls.Config{
			Certificates:          []tls.Certificate{cert},
			ClientAuth:            tls.RequireAnyClientCert,
			VerifyPeerCertificate: verify,
			MinVersion:            tls.VersionTLS13,
			NextProtos:            []string{alpnGossip},
		},
		client: &tls.Config{
			Certificates:          []tls.Certificate{cert},
			InsecureSkipVerify:    true, // identity is checked by VerifyPeerCertificate, not by CA chain
			VerifyPeerCertificate: verify,
			MinVersion:            tls.VersionTLS13,
			NextProtos:            []string{alpnGossip},
		},
		qconf: &quic.Config{
			EnableDatagrams: true, MaxIdleTimeout: idleTimeout, KeepAlivePeriod: keepAlive,
			HandshakeIdleTimeout: handshakeTime,
		},
		packets: make(chan *memberlist.Packet),
		streams: make(chan net.Conn),
		done:    make(chan struct{}),
		conns:   map[string]*quic.Conn{},
		dialing: map[string]bool{},
	}
	t.ln, err = t.qt.Listen(t.server, t.qconf)
	if err != nil {
		_ = udp.Close()
		return nil, fmt.Errorf("listening for gossip: %w", err)
	}
	t.wg.Add(1)
	go t.accept()
	return t, nil
}

// identityCertificate is a self-signed certificate carrying the node's Ed25519 key.
func identityCertificate(id *trust.Identity) (tls.Certificate, error) {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: id.Public().Short()},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(100 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, id.Signer().Public(), id.Signer())
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("creating identity certificate: %w", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: id.Signer()}, nil
}

// certIdentity is the identity in a peer's leaf certificate.
func certIdentity(rawCerts [][]byte) (trust.PublicKey, error) {
	if len(rawCerts) == 0 {
		return trust.PublicKey{}, errors.New("peer presented no certificate")
	}
	c, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return trust.PublicKey{}, err
	}
	pub, ok := c.PublicKey.(ed25519.PublicKey)
	if !ok || len(pub) != identityLen {
		return trust.PublicKey{}, errors.New("peer certificate is not an Ed25519 identity")
	}
	var peer trust.PublicKey
	copy(peer[:], pub)
	return peer, nil
}

// connIdentity is the verified identity behind an established connection.
func connIdentity(conn *quic.Conn) (trust.PublicKey, error) {
	certs := conn.ConnectionState().TLS.PeerCertificates
	if len(certs) == 0 {
		return trust.PublicKey{}, errors.New("peer presented no certificate")
	}
	return certIdentity([][]byte{certs[0].Raw})
}

// accept adopts incoming member connections until the listener closes.
func (t *quicTransport) accept() {
	defer t.wg.Done()
	for {
		conn, err := t.ln.Accept(context.Background())
		if err != nil {
			return
		}
		t.adopt(conn)
	}
}

// adopt starts serving a connection: its datagrams become packets and its
// streams are handed to memberlist. It replaces any earlier connection to the
// same address, which dies on its own.
func (t *quicTransport) adopt(conn *quic.Conn) {
	peer, err := connIdentity(conn)
	if err != nil {
		_ = conn.CloseWithError(1, err.Error())
		return
	}
	addr := conn.RemoteAddr().String()
	t.mu.Lock()
	t.conns[addr] = conn
	t.mu.Unlock()
	slog.Debug("gossip connection", "peer", peer.Short(), "addr", addr)

	t.wg.Add(2)
	go func() {
		defer t.wg.Done()
		defer t.forget(addr, conn)
		for {
			b, err := conn.ReceiveDatagram(context.Background())
			if err != nil {
				return
			}
			if !t.set.Valid(peer) {
				_ = conn.CloseWithError(1, "not a member")
				return
			}
			select {
			case t.packets <- &memberlist.Packet{Buf: b, From: conn.RemoteAddr(), Timestamp: time.Now()}:
			case <-t.done:
				return
			}
		}
	}()
	go func() {
		defer t.wg.Done()
		for {
			s, err := conn.AcceptStream(context.Background())
			if err != nil {
				return
			}
			if !t.set.Valid(peer) {
				_ = conn.CloseWithError(1, "not a member")
				return
			}
			select {
			case t.streams <- &streamConn{Stream: s, local: conn.LocalAddr(), remote: conn.RemoteAddr()}:
			case <-t.done:
				_ = conn.CloseWithError(0, "shutdown")
				return
			}
		}
	}()
}

// forget drops conn from the table if it is still the one recorded for addr.
func (t *quicTransport) forget(addr string, conn *quic.Conn) {
	t.mu.Lock()
	if t.conns[addr] == conn {
		delete(t.conns, addr)
	}
	t.mu.Unlock()
}

func (t *quicTransport) lookup(addr string) *quic.Conn {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.conns[addr]
}

// dial connects to a peer's gossip address and adopts the connection.
func (t *quicTransport) dial(ctx context.Context, addr string) (*quic.Conn, error) {
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	conn, err := t.qt.Dial(ctx, ua, t.client, t.qconf)
	if err != nil {
		return nil, fmt.Errorf("gossip to %s: %w", addr, err)
	}
	if conn.ConnectionState().TLS.NegotiatedProtocol != alpnGossip {
		_ = conn.CloseWithError(1, "wrong protocol")
		return nil, fmt.Errorf("gossip to %s: peer does not speak %s", addr, alpnGossip)
	}
	t.adopt(conn)
	return conn, nil
}

// dialAsync starts a connection attempt to addr unless one is under way.
func (t *quicTransport) dialAsync(addr string) {
	t.mu.Lock()
	if t.dialing[addr] {
		t.mu.Unlock()
		return
	}
	t.dialing[addr] = true
	t.mu.Unlock()
	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		defer func() {
			t.mu.Lock()
			delete(t.dialing, addr)
			t.mu.Unlock()
		}()
		ctx, cancel := context.WithTimeout(context.Background(), handshakeTime)
		defer cancel()
		if _, err := t.dial(ctx, addr); err != nil {
			slog.Debug("could not connect for gossip", "addr", addr, "err", err)
		}
	}()
}

// FinalAdvertiseAddr implements memberlist.Transport.
func (t *quicTransport) FinalAdvertiseAddr(ip string, port int) (net.IP, int, error) {
	if ip == "" {
		local := t.udp.LocalAddr().(*net.UDPAddr)
		if local.IP.IsUnspecified() {
			return nil, 0, errors.New("an advertise address is required when binding a wildcard")
		}
		return local.IP, local.Port, nil
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return nil, 0, fmt.Errorf("invalid advertise address %q", ip)
	}
	if port == 0 {
		port = t.udp.LocalAddr().(*net.UDPAddr).Port
	}
	return parsed, port, nil
}

// WriteTo implements memberlist.Transport.
func (t *quicTransport) WriteTo(b []byte, addr string) (time.Time, error) {
	return t.WriteToAddress(b, memberlist.Address{Addr: addr})
}

// WriteToAddress implements memberlist.NodeAwareTransport: the packet goes as
// a datagram on the connection to the peer. Without a usable connection the
// packet is silently dropped, as UDP would, and a connection attempt starts:
// memberlist treats a lost probe as a sign of failure and an error as its own
// fault, so dropping is what makes failure detection work.
func (t *quicTransport) WriteToAddress(b []byte, a memberlist.Address) (time.Time, error) {
	t.life.RLock()
	defer t.life.RUnlock()
	select {
	case <-t.done:
		return time.Now(), nil
	default:
	}
	conn := t.lookup(a.Addr)
	if conn == nil {
		t.dialAsync(a.Addr)
		return time.Now(), nil
	}
	if err := conn.SendDatagram(b); err != nil {
		var tooLarge *quic.DatagramTooLargeError
		if errors.As(err, &tooLarge) {
			return time.Time{}, fmt.Errorf("gossip packet of %d bytes exceeds %d", len(b), tooLarge.MaxDatagramPayloadSize)
		}
		t.forget(a.Addr, conn)
		slog.Debug("gossip connection lost", "addr", a.Addr, "err", err)
	}
	return time.Now(), nil
}

// PacketCh implements memberlist.Transport.
func (t *quicTransport) PacketCh() <-chan *memberlist.Packet { return t.packets }

// DialTimeout implements memberlist.Transport.
func (t *quicTransport) DialTimeout(addr string, timeout time.Duration) (net.Conn, error) {
	return t.DialAddressTimeout(memberlist.Address{Addr: addr}, timeout)
}

// DialAddressTimeout implements memberlist.NodeAwareTransport: a stream on the
// connection to the peer, connecting first if needed. A connection that no
// longer accepts streams is replaced.
func (t *quicTransport) DialAddressTimeout(a memberlist.Address, timeout time.Duration) (net.Conn, error) {
	select {
	case <-t.done:
		return nil, errors.New("gossip transport is shut down")
	default:
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	conn := t.lookup(a.Addr)
	if conn != nil {
		if s, err := conn.OpenStreamSync(ctx); err == nil {
			return &streamConn{Stream: s, local: conn.LocalAddr(), remote: conn.RemoteAddr()}, nil
		}
		t.forget(a.Addr, conn)
	}
	conn, err := t.dial(ctx, a.Addr)
	if err != nil {
		return nil, err
	}
	s, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("gossip to %s: %w", a.Addr, err)
	}
	return &streamConn{Stream: s, local: conn.LocalAddr(), remote: conn.RemoteAddr()}, nil
}

// StreamCh implements memberlist.Transport.
func (t *quicTransport) StreamCh() <-chan net.Conn { return t.streams }

// Shutdown implements memberlist.Transport. Safe to call more than once.
func (t *quicTransport) Shutdown() error {
	t.once.Do(func() {
		close(t.done)
		_ = t.ln.Close()
		t.mu.Lock()
		for _, c := range t.conns {
			_ = c.CloseWithError(0, "shutdown")
		}
		t.mu.Unlock()
		t.err = t.qt.Close()
		_ = t.udp.Close()
		t.wg.Wait()
	})
	return t.err
}

// streamConn presents a QUIC stream as a net.Conn.
type streamConn struct {
	*quic.Stream
	local, remote net.Addr
}

func (s *streamConn) LocalAddr() net.Addr  { return s.local }
func (s *streamConn) RemoteAddr() net.Addr { return s.remote }

// Close ends both directions: the send side cleanly, the receive side by
// telling the peer to stop.
func (s *streamConn) Close() error {
	s.CancelRead(0)
	return s.Stream.Close()
}
