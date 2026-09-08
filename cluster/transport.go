package cluster

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"sync"
	"time"

	"github.com/hashicorp/memberlist"
	"github.com/jdpanderson/cheesecloth/trust"
)

// The gossip transport authenticates every message with node identities, so no
// cluster-wide key exists. Packets: version || sender || nonce || AES-256-GCM
// under a pairwise key from X25519. Streams: mutual TLS 1.3 with self-signed
// certificates for the nodes' Ed25519 keys, accepted only for valid members.

const (
	packetVersion  = 1
	identityLen    = 32
	nonceLen       = 12
	tagLen         = 16
	packetOverhead = 1 + identityLen + nonceLen + tagLen
	gossipKDFInfo  = "cheesecloth/gossip/v1"
	alpn           = "cheesecloth-gossip/1"
	handshakeTime  = 10 * time.Second
)

type secureTransport struct {
	inner   *memberlist.NetTransport
	id      *trust.Identity
	set     *trust.Set
	book    *addrBook
	server  *tls.Config
	client  *tls.Config
	packets chan *memberlist.Packet
	streams chan net.Conn
	done    chan struct{}
	wg      sync.WaitGroup

	keyMu sync.Mutex
	keys  map[trust.PublicKey]cipher.AEAD
}

var _ memberlist.NodeAwareTransport = (*secureTransport)(nil)

func newSecureTransport(inner *memberlist.NetTransport, id *trust.Identity, set *trust.Set, book *addrBook) (*secureTransport, error) {
	cert, err := identityCertificate(id)
	if err != nil {
		return nil, err
	}
	verify := func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("peer presented no certificate")
		}
		c, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return err
		}
		pub, ok := c.PublicKey.(ed25519.PublicKey)
		if !ok || len(pub) != identityLen {
			return errors.New("peer certificate is not an Ed25519 identity")
		}
		var peer trust.PublicKey
		copy(peer[:], pub)
		if !set.Valid(peer) {
			return fmt.Errorf("peer %s is not a member", peer.Short())
		}
		return nil
	}
	t := &secureTransport{
		inner: inner, id: id, set: set, book: book,
		server: &tls.Config{
			Certificates:          []tls.Certificate{cert},
			ClientAuth:            tls.RequireAnyClientCert,
			VerifyPeerCertificate: verify,
			MinVersion:            tls.VersionTLS13,
			NextProtos:            []string{alpn},
		},
		client: &tls.Config{
			Certificates:          []tls.Certificate{cert},
			InsecureSkipVerify:    true, // identity is checked by VerifyPeerCertificate, not by CA chain
			VerifyPeerCertificate: verify,
			MinVersion:            tls.VersionTLS13,
			NextProtos:            []string{alpn},
		},
		packets: make(chan *memberlist.Packet),
		streams: make(chan net.Conn),
		done:    make(chan struct{}),
		keys:    map[trust.PublicKey]cipher.AEAD{},
	}
	t.wg.Add(2)
	go t.readPackets()
	go t.acceptStreams()
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

// pairKey returns the AEAD shared with peer, deriving and caching it on first use.
func (t *secureTransport) pairKey(peer trust.PublicKey) (cipher.AEAD, error) {
	t.keyMu.Lock()
	defer t.keyMu.Unlock()
	if aead, ok := t.keys[peer]; ok {
		return aead, nil
	}
	dh, err := t.set.DHKeyOf(peer)
	if err != nil {
		return nil, err
	}
	ss, err := t.id.SharedSecret(dh)
	if err != nil {
		return nil, err
	}
	me := t.id.Public()
	lo, hi := me, peer
	if hi.String() < lo.String() {
		lo, hi = hi, lo
	}
	salt := append(append([]byte(nil), lo[:]...), hi[:]...)
	key, err := hkdf.Key(sha256.New, ss, salt, gossipKDFInfo, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	t.keys[peer] = aead
	return aead, nil
}

// FinalAdvertiseAddr implements memberlist.Transport.
func (t *secureTransport) FinalAdvertiseAddr(ip string, port int) (net.IP, int, error) {
	return t.inner.FinalAdvertiseAddr(ip, port)
}

// WriteTo implements memberlist.Transport.
func (t *secureTransport) WriteTo(b []byte, addr string) (time.Time, error) {
	return t.WriteToAddress(b, memberlist.Address{Addr: addr})
}

// WriteToAddress implements memberlist.NodeAwareTransport: encrypt to the
// identity known for the address, or fail so memberlist retries later.
func (t *secureTransport) WriteToAddress(b []byte, a memberlist.Address) (time.Time, error) {
	peer, ok := t.book.lookup(a.Addr)
	if !ok {
		return time.Time{}, fmt.Errorf("no identity known for %s yet", a.Addr)
	}
	aead, err := t.pairKey(peer)
	if err != nil {
		return time.Time{}, err
	}
	me := t.id.Public()
	out := make([]byte, 0, packetOverhead+len(b))
	out = append(out, packetVersion)
	out = append(out, me[:]...)
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return time.Time{}, err
	}
	out = append(out, nonce...)
	ad := append(append([]byte(nil), out[:1+identityLen]...), peer[:]...)
	out = aead.Seal(out, nonce, b, ad)
	return t.inner.WriteToAddress(out, a)
}

// PacketCh implements memberlist.Transport.
func (t *secureTransport) PacketCh() <-chan *memberlist.Packet { return t.packets }

func (t *secureTransport) readPackets() {
	defer t.wg.Done()
	for {
		select {
		case <-t.done:
			return
		case p := <-t.inner.PacketCh():
			plain, sender, err := t.openPacket(p.Buf)
			if err != nil {
				slog.Debug("dropping gossip packet", "from", p.From, "err", err)
				continue
			}
			t.book.set(p.From.String(), sender)
			select {
			case t.packets <- &memberlist.Packet{Buf: plain, From: p.From, Timestamp: p.Timestamp}:
			case <-t.done:
				return
			}
		}
	}
}

// openPacket authenticates and decrypts an incoming packet, returning the sender.
func (t *secureTransport) openPacket(buf []byte) ([]byte, trust.PublicKey, error) {
	if len(buf) < packetOverhead || buf[0] != packetVersion {
		return nil, trust.PublicKey{}, errors.New("not a cheesecloth gossip packet")
	}
	var sender trust.PublicKey
	copy(sender[:], buf[1:1+identityLen])
	if !t.set.Valid(sender) {
		return nil, trust.PublicKey{}, fmt.Errorf("sender %s is not a member", sender.Short())
	}
	aead, err := t.pairKey(sender)
	if err != nil {
		return nil, trust.PublicKey{}, err
	}
	me := t.id.Public()
	ad := append(append([]byte(nil), buf[:1+identityLen]...), me[:]...)
	nonce := buf[1+identityLen : 1+identityLen+nonceLen]
	plain, err := aead.Open(nil, nonce, buf[1+identityLen+nonceLen:], ad)
	if err != nil {
		return nil, trust.PublicKey{}, fmt.Errorf("from %s: %w", sender.Short(), err)
	}
	return plain, sender, nil
}

// DialTimeout implements memberlist.Transport.
func (t *secureTransport) DialTimeout(addr string, timeout time.Duration) (net.Conn, error) {
	return t.DialAddressTimeout(memberlist.Address{Addr: addr}, timeout)
}

// DialAddressTimeout implements memberlist.NodeAwareTransport with a mutually
// authenticated TLS session; the peer must prove a member identity.
func (t *secureTransport) DialAddressTimeout(a memberlist.Address, timeout time.Duration) (net.Conn, error) {
	raw, err := t.inner.DialAddressTimeout(a, timeout)
	if err != nil {
		return nil, err
	}
	conn := tls.Client(raw, t.client)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("gossip tls to %s: %w", a.Addr, err)
	}
	if conn.ConnectionState().NegotiatedProtocol != alpn {
		_ = conn.Close()
		return nil, fmt.Errorf("gossip tls to %s: peer does not speak %s", a.Addr, alpn)
	}
	return conn, nil
}

// StreamCh implements memberlist.Transport.
func (t *secureTransport) StreamCh() <-chan net.Conn { return t.streams }

func (t *secureTransport) acceptStreams() {
	defer t.wg.Done()
	for {
		select {
		case <-t.done:
			return
		case raw := <-t.inner.StreamCh():
			t.wg.Add(1)
			go func() {
				defer t.wg.Done()
				conn := tls.Server(raw, t.server)
				ctx, cancel := context.WithTimeout(context.Background(), handshakeTime)
				defer cancel()
				if err := conn.HandshakeContext(ctx); err != nil {
					slog.Debug("rejecting gossip stream", "from", raw.RemoteAddr(), "err", err)
					_ = raw.Close()
					return
				}
				select {
				case t.streams <- conn:
				case <-t.done:
					_ = conn.Close()
				}
			}()
		}
	}
}

// Shutdown implements memberlist.Transport.
func (t *secureTransport) Shutdown() error {
	err := t.inner.Shutdown()
	close(t.done)
	t.wg.Wait()
	return err
}
