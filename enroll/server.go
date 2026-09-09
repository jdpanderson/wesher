package enroll

import (
	"context"
	"crypto/hmac"
	"errors"
	"log/slog"
	"net"
	"sync"

	"github.com/jdpanderson/cheesecloth/trust"
)

// Server admits joiners who prove knowledge of a pending token.
type Server struct {
	Identity *trust.Identity
	Tokens   *TokenStore
	Root     trust.PublicKey
	// Admit signs and records an admission of the joiner (and distributes it);
	// it must return the admission and the records the joiner should start with.
	Admit func(joiner trust.PublicKey, dh trust.DHKey, name string) (trust.Admission, trust.Records, error)
	// GossipAddr is this node's memberlist ip:port, handed to the joiner.
	GossipAddr string

	wg sync.WaitGroup
}

// Serve accepts enrolment connections until ln is closed.
func (s *Server) Serve(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			s.wg.Wait()
			return
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() { _ = conn.Close() }()
			if err := s.handle(conn); err != nil && !errors.Is(err, errSilent) {
				slog.Warn("enrolment failed", "from", conn.RemoteAddr(), "err", err)
			}
		}()
	}
}

// errSilent marks failures that must not be reported to the peer, so the
// server is not an oracle for token guessing.
var errSilent = errors.New("silent")

func (s *Server) handle(conn net.Conn) error {
	setDeadline(conn)
	var h hello
	if err := readFrame(conn, &h); err != nil {
		return err
	}
	if h.Version != Version || len(h.TokenID) != tokenIDLen || len(h.Nonce) != nonceLen || h.Name == "" {
		return errors.New("malformed hello")
	}
	var id tokenID
	copy(id[:], h.TokenID)
	key, ok := s.Tokens.lookup(id)
	if !ok {
		slog.Debug("enrolment with unknown or expired token", "from", conn.RemoteAddr(), "name", h.Name)
		return errSilent
	}

	ss, err := s.Identity.SharedSecret(h.DH)
	if err != nil {
		return err
	}
	nM, err := randomNonce()
	if err != nil {
		return err
	}
	k := deriveKeys(ss, key, h.Nonce, nM)
	tr := transcript(h.Identity, h.DH, s.Identity.Public(), s.Identity.DHPublic(), h.Nonce, nM, h.Name)
	if err = writeFrame(conn, challenge{
		Identity: s.Identity.Public(), DH: s.Identity.DHPublic(), Nonce: nM, MAC: mac(k.mac, labelMember, tr),
	}); err != nil {
		return err
	}

	var p proof
	if err = readFrame(conn, &p); err != nil {
		return err
	}
	if !hmac.Equal(p.MAC, mac(k.mac, labelJoiner, tr)) {
		return errors.New("joiner could not prove knowledge of the token")
	}
	s.Tokens.consume(id)

	adm, records, err := s.Admit(h.Identity, h.DH, h.Name)
	if err != nil {
		return err
	}
	w := Welcome{Root: s.Root, Records: records, Admission: adm, GossipAddr: s.GossipAddr}
	plain, err := marshal(w)
	if err != nil {
		return err
	}
	sealed, err := seal(k.enc, plain)
	if err != nil {
		return err
	}
	slog.Info("enrolled node", "name", h.Name, "identity", h.Identity.Short(), "from", conn.RemoteAddr())
	return writeFrame(conn, sealed)
}

// Join enrols with the member at addr using token, proving knowledge of it and
// verifying the member's proof in return.
func Join(ctx context.Context, addr, token string, id *trust.Identity, name string) (*Welcome, trust.PublicKey, error) {
	key, err := DecodeToken(token)
	if err != nil {
		return nil, trust.PublicKey{}, err
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, trust.PublicKey{}, err
	}
	defer func() { _ = conn.Close() }()
	setDeadline(conn)

	nJ, err := randomNonce()
	if err != nil {
		return nil, trust.PublicKey{}, err
	}
	tid := idOf(key)
	if err = writeFrame(conn, hello{
		Version: Version, TokenID: tid[:], Identity: id.Public(), DH: id.DHPublic(), Nonce: nJ, Name: name,
	}); err != nil {
		return nil, trust.PublicKey{}, err
	}

	var c challenge
	if err = readFrame(conn, &c); err != nil {
		return nil, trust.PublicKey{}, errors.New("member closed the connection; is the join key valid and unexpired?")
	}
	if len(c.Nonce) != nonceLen {
		return nil, trust.PublicKey{}, errors.New("malformed challenge")
	}
	ss, err := id.SharedSecret(c.DH)
	if err != nil {
		return nil, trust.PublicKey{}, err
	}
	k := deriveKeys(ss, key, nJ, c.Nonce)
	tr := transcript(id.Public(), id.DHPublic(), c.Identity, c.DH, nJ, c.Nonce, name)
	if !hmac.Equal(c.MAC, mac(k.mac, labelMember, tr)) {
		return nil, trust.PublicKey{}, errors.New("member could not prove knowledge of the join key")
	}
	if err = writeFrame(conn, proof{MAC: mac(k.mac, labelJoiner, tr)}); err != nil {
		return nil, trust.PublicKey{}, err
	}

	var sealed []byte
	if err = readFrame(conn, &sealed); err != nil {
		return nil, trust.PublicKey{}, err
	}
	plain, err := open(k.enc, sealed)
	if err != nil {
		return nil, trust.PublicKey{}, errors.New("could not decrypt the welcome message")
	}
	var w Welcome
	if err := unmarshal(plain, &w); err != nil {
		return nil, trust.PublicKey{}, err
	}

	// Trust nothing in the welcome that the records do not prove.
	set := trust.NewSet(w.Root)
	set.Merge(w.Records)
	if !set.Valid(c.Identity) {
		return nil, trust.PublicKey{}, errors.New("member is not a valid member of the cluster it described")
	}
	if w.Admission.Identity != id.Public() || w.Admission.Admitter != c.Identity {
		return nil, trust.PublicKey{}, errors.New("welcome carries an admission for someone else")
	}
	if _, err := set.AddAdmission(w.Admission); err != nil {
		return nil, trust.PublicKey{}, err
	}
	if !set.Valid(id.Public()) {
		return nil, trust.PublicKey{}, errors.New("admission does not make us a member")
	}
	return &w, c.Identity, nil
}
