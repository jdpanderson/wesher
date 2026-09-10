package enroll

import (
	"net"
	"testing"
	"time"

	"github.com/jdpanderson/cheesecloth/trust"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newID(t *testing.T) *trust.Identity {
	t.Helper()
	id, err := trust.NewIdentity()
	require.NoError(t, err)
	return id
}

// joinTCP dials addr and runs the joiner's side of the exchange.
func joinTCP(t *testing.T, addr, token string, id *trust.Identity, name string) (*Welcome, trust.PublicKey, error) {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	return Join(conn, token, id, name)
}

// member starts an enrolment server for a one-node cluster rooted at its identity.
func member(t *testing.T) (*Server, *trust.Set, string) {
	t.Helper()
	id := newID(t)
	set := trust.NewSet(id.Public())
	_, err := set.AddAdmission(trust.SelfAdmit(id, "root", time.Now()))
	require.NoError(t, err)
	srv := &Server{
		Identity: id, Tokens: NewTokenStore(), Root: id.Public(), GossipAddr: "192.0.2.1:7946",
		Admit: func(joiner trust.PublicKey, dh trust.DHKey, name string) (trust.Admission, trust.Records, error) {
			a := trust.Admit(id, joiner, dh, name, 2, time.Now())
			if _, aerr := set.AddAdmission(a); aerr != nil {
				return trust.Admission{}, trust.Records{}, aerr
			}
			return a, set.Records(), nil
		},
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go srv.Serve(ln)
	t.Cleanup(func() { _ = ln.Close() })
	return srv, set, ln.Addr().String()
}

func Test_Join_happyPath(t *testing.T) {
	srv, set, addr := member(t)
	token, err := srv.Tokens.Mint(time.Minute, 1)
	require.NoError(t, err)

	joiner := newID(t)
	w, memberID, err := joinTCP(t, addr, token, joiner, "joiner")
	require.NoError(t, err)
	assert.Equal(t, srv.Identity.Public(), memberID)
	assert.Equal(t, srv.Root, w.Root)
	assert.Equal(t, "192.0.2.1:7946", w.GossipAddr)
	assert.Equal(t, joiner.Public(), w.Admission.Identity)
	assert.Equal(t, "joiner", w.Admission.Name)
	assert.True(t, set.Valid(joiner.Public()), "member's set now includes the joiner")
	assert.Len(t, w.Records.Admissions, 2)
	assert.Equal(t, 0, srv.Tokens.Pending(), "single-use token is consumed")

	// the token cannot be reused
	_, _, err = joinTCP(t, addr, token, newID(t), "again")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "closed the connection")
}

func Test_Join_multiUseAndExpiry(t *testing.T) {
	srv, _, addr := member(t)
	token, err := srv.Tokens.Mint(time.Minute, 2)
	require.NoError(t, err)
	_, _, err = joinTCP(t, addr, token, newID(t), "one")
	require.NoError(t, err)
	assert.Equal(t, 1, srv.Tokens.Pending())
	_, _, err = joinTCP(t, addr, token, newID(t), "two")
	require.NoError(t, err)
	assert.Equal(t, 0, srv.Tokens.Pending())

	// expiry
	now := time.Now()
	srv.Tokens.now = func() time.Time { return now }
	token, err = srv.Tokens.Mint(time.Minute, 1)
	require.NoError(t, err)
	srv.Tokens.now = func() time.Time { return now.Add(2 * time.Minute) }
	_, _, err = joinTCP(t, addr, token, newID(t), "late")
	require.Error(t, err)
	assert.Equal(t, 0, srv.Tokens.Pending())
}

func Test_Join_wrongToken(t *testing.T) {
	srv, _, addr := member(t)
	_, err := srv.Tokens.Mint(time.Minute, 1)
	require.NoError(t, err)

	// a different, well-formed token: unknown id, silent close
	other, err := NewTokenStore().Mint(time.Minute, 1)
	require.NoError(t, err)
	_, _, err = joinTCP(t, addr, other, newID(t), "x")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "closed the connection")
	assert.Equal(t, 1, srv.Tokens.Pending(), "a failed attempt does not consume the token")

	// malformed token
	_, _, err = joinTCP(t, addr, "nope", newID(t), "x")
	assert.ErrorContains(t, err, "join key")
}

// A man in the middle who knows the token id but not the token cannot pass as the member.
func Test_Join_memberMustProveToken(t *testing.T) {
	srv, _, addr := member(t)
	real, err := srv.Tokens.Mint(time.Minute, 1)
	require.NoError(t, err)
	key, _ := DecodeToken(real)

	// impostor: same token id (it saw the hello), different key
	impostor := &Server{Identity: newID(t), Tokens: NewTokenStore(), Root: srv.Root, GossipAddr: "x",
		Admit: func(trust.PublicKey, trust.DHKey, string) (trust.Admission, trust.Records, error) {
			return trust.Admission{}, trust.Records{}, nil
		}}
	wrong := make([]byte, len(key))
	copy(wrong, key)
	wrong[0] ^= 1
	impostor.Tokens.tokens[idOf(key)] = &token{key: wrong, expires: time.Now().Add(time.Minute), uses: 1}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()
	go impostor.Serve(ln)

	_, _, err = joinTCP(t, ln.Addr().String(), real, newID(t), "victim")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "member could not prove knowledge")
	_ = addr
}

func Test_Join_welcomeMustBeConsistent(t *testing.T) {
	// a server whose Admit does not actually make the joiner a member of the described cluster
	id := newID(t)
	otherRoot := newID(t)
	srv := &Server{Identity: id, Tokens: NewTokenStore(), Root: otherRoot.Public(), GossipAddr: "x",
		Admit: func(trust.PublicKey, trust.DHKey, string) (trust.Admission, trust.Records, error) {
			return trust.Admission{}, trust.Records{}, nil
		}}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()
	go srv.Serve(ln)
	token, err := srv.Tokens.Mint(time.Minute, 1)
	require.NoError(t, err)

	_, _, err = joinTCP(t, ln.Addr().String(), token, newID(t), "j")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a valid member")
}

func Test_TokenStore(t *testing.T) {
	s := NewTokenStore()
	_, err := s.Mint(0, 1)
	assert.Error(t, err)
	_, err = s.Mint(time.Minute, 0)
	assert.Error(t, err)
	tok, err := s.Mint(time.Minute, 1)
	require.NoError(t, err)
	key, err := DecodeToken(tok)
	require.NoError(t, err)
	assert.Len(t, key, tokenLen)
	_, ok := s.lookup(idOf(key))
	assert.True(t, ok)
	s.consume(idOf(key))
	_, ok = s.lookup(idOf(key))
	assert.False(t, ok)
}

func Test_transcriptAndKeys(t *testing.T) {
	a, b := newID(t), newID(t)
	nJ, nM := []byte("nJ"), []byte("nM")
	t1 := transcript(a.Public(), a.DHPublic(), b.Public(), b.DHPublic(), nJ, nM, "n")
	t2 := transcript(a.Public(), a.DHPublic(), b.Public(), b.DHPublic(), nJ, nM, "m")
	assert.NotEqual(t, t1, t2)
	assert.NotEqual(t, mac([]byte("k"), labelMember, t1), mac([]byte("k"), labelJoiner, t1), "direction labels differ")

	ss, _ := a.SharedSecret(b.DHPublic())
	k1 := deriveKeys(ss, []byte("token"), nJ, nM)
	k2 := deriveKeys(ss, []byte("other"), nJ, nM)
	assert.NotEqual(t, k1.mac, k2.mac, "the token is mixed into the keys")
	assert.Len(t, k1.mac, 32)
}
