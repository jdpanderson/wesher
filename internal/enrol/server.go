package enrol

import (
	"crypto/hmac"
	"errors"
	"fmt"
	"log/slog"
	"net"

	"github.com/jdpanderson/cheesecloth/internal/trust"
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
}

// Conn is a connection whose peer identity the transport has verified (a QUIC
// stream); the exchange requires the identities in the messages to match it.
type Conn interface {
	net.Conn
	PeerIdentity() trust.PublicKey
}

// bound checks that the identity a message claims is the one on the wire.
func bound(conn Conn, claimed trust.PublicKey) error {
	if conn.PeerIdentity() != claimed {
		return errors.New("claimed identity does not match the connection's")
	}
	return nil
}

// Handle runs the member's side of one enrolment on conn and closes it.
func (s *Server) Handle(conn Conn) {
	defer func() { _ = conn.Close() }()
	if err := s.handle(conn); err != nil && !errors.Is(err, errSilent) {
		slog.Warn("enrolment failed", "from", conn.RemoteAddr(), "err", err)
	}
}

// errSilent marks failures that must not be reported to the peer, so the
// server is not an oracle for token guessing.
var errSilent = errors.New("silent")

func (s *Server) handle(conn Conn) error {
	setDeadline(conn)
	var h hello
	if err := readFrame(conn, &h); err != nil {
		return err
	}
	if h.Version != Version || len(h.TokenID) != tokenIDLen || len(h.Nonce) != nonceLen || h.Name == "" {
		return errors.New("malformed hello")
	}
	if err := bound(conn, h.Identity); err != nil {
		return err
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
	k := deriveKey(ss, key, h.Nonce, nM)
	tr := transcript(h.Identity, h.DH, s.Identity.Public(), s.Identity.DHPublic(), h.Nonce, nM, h.Name)
	if err = writeFrame(conn, challenge{
		Identity: s.Identity.Public(), DH: s.Identity.DHPublic(), Nonce: nM, MAC: mac(k, labelMember, tr),
	}); err != nil {
		return err
	}

	var p proof
	if err = readFrame(conn, &p); err != nil {
		return err
	}
	if !hmac.Equal(p.MAC, mac(k, labelJoiner, tr)) {
		return errors.New("joiner could not prove knowledge of the token")
	}
	if !s.Tokens.consume(id) {
		return errors.New("token was spent or expired during the exchange")
	}

	adm, records, err := s.Admit(h.Identity, h.DH, h.Name)
	if err != nil {
		return err
	}
	slog.Info("enrolled node", "name", h.Name, "identity", h.Identity.Short(), "from", conn.RemoteAddr())
	return writeFrame(conn, Welcome{Root: s.Root, Records: records, Admission: adm, GossipAddr: s.GossipAddr})
}

// Join enrols with the member on conn using token, proving knowledge of it and
// verifying the member's proof in return. The caller owns conn.
func Join(conn Conn, token string, id *trust.Identity, name string) (*Welcome, error) {
	key, err := DecodeToken(token)
	if err != nil {
		return nil, err
	}
	setDeadline(conn)

	nJ, err := randomNonce()
	if err != nil {
		return nil, err
	}
	tid := idOf(key)
	if err = writeFrame(conn, hello{
		Version: Version, TokenID: tid[:], Identity: id.Public(), DH: id.DHPublic(), Nonce: nJ, Name: name,
	}); err != nil {
		return nil, err
	}

	var c challenge
	if err = readFrame(conn, &c); err != nil {
		return nil, fmt.Errorf("member closed the connection (is the join key valid and unexpired?): %w", err)
	}
	if len(c.Nonce) != nonceLen {
		return nil, errors.New("malformed challenge")
	}
	if err = bound(conn, c.Identity); err != nil {
		return nil, err
	}
	ss, err := id.SharedSecret(c.DH)
	if err != nil {
		return nil, err
	}
	k := deriveKey(ss, key, nJ, c.Nonce)
	tr := transcript(id.Public(), id.DHPublic(), c.Identity, c.DH, nJ, c.Nonce, name)
	if !hmac.Equal(c.MAC, mac(k, labelMember, tr)) {
		return nil, errors.New("member could not prove knowledge of the join key")
	}
	if err = writeFrame(conn, proof{MAC: mac(k, labelJoiner, tr)}); err != nil {
		return nil, err
	}

	var w Welcome
	if err = readFrame(conn, &w); err != nil {
		return nil, err
	}

	// Trust nothing in the welcome that the records do not prove.
	set := trust.NewSet(w.Root)
	set.Merge(w.Records)
	if !set.Valid(c.Identity) {
		return nil, errors.New("member is not a valid member of the cluster it described")
	}
	if w.Admission.Identity != id.Public() || w.Admission.Admitter != c.Identity {
		return nil, errors.New("welcome carries an admission for someone else")
	}
	if _, err := set.AddAdmission(w.Admission); err != nil {
		return nil, err
	}
	if !set.Valid(id.Public()) {
		return nil, errors.New("admission does not make us a member")
	}
	w.Member = c.Identity
	return &w, nil
}
