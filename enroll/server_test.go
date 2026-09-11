package enroll

import (
	"net"
	"testing"
	"time"

	"github.com/jdpanderson/cheesecloth/trust"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Failure paths of the exchange; the successful and token-related paths are in enroll_test.go.

func Test_handle_malformedHello(t *testing.T) {
	srv, _ := member(t)
	joiner := newID(t)
	conn := pipeTo(t, srv, joiner.Public())
	setDeadline(conn)
	require.NoError(t, writeFrame(conn, hello{Version: Version + 1, TokenID: make([]byte, tokenIDLen), Identity: joiner.Public(), Nonce: make([]byte, nonceLen), Name: "j"}))
	var c challenge
	assert.Error(t, readFrame(conn, &c), "the member hangs up without a challenge")
}

func Test_handle_badProof(t *testing.T) {
	srv, _ := member(t)
	tok, err := srv.Tokens.Mint(time.Minute, 1)
	require.NoError(t, err)
	key, err := DecodeToken(tok)
	require.NoError(t, err)
	joiner := newID(t)

	conn := pipeTo(t, srv, joiner.Public())
	setDeadline(conn)
	tid := idOf(key)
	nJ, _ := randomNonce()
	require.NoError(t, writeFrame(conn, hello{Version: Version, TokenID: tid[:], Identity: joiner.Public(), DH: joiner.DHPublic(), Nonce: nJ, Name: "j"}))
	var c challenge
	require.NoError(t, readFrame(conn, &c), "a known token id gets a challenge")

	// prove with the wrong key: knowing the id is not knowing the token
	ss, err := joiner.SharedSecret(c.DH)
	require.NoError(t, err)
	k := deriveKeys(ss, append([]byte{0}, key[1:]...), nJ, c.Nonce)
	tr := transcript(joiner.Public(), joiner.DHPublic(), c.Identity, c.DH, nJ, c.Nonce, "j")
	require.NoError(t, writeFrame(conn, proof{MAC: mac(k.mac, labelJoiner, tr)}))
	var sealed []byte
	assert.Error(t, readFrame(conn, &sealed), "no welcome")
	assert.Equal(t, 1, srv.Tokens.Pending(), "a failed proof does not spend the token")
}

func Test_Join_errors(t *testing.T) {
	id, other := newID(t), newID(t)
	c1, c2 := net.Pipe()
	defer func() { _ = c1.Close(); _ = c2.Close() }()
	_, _, err := Join(identified{c1, other.Public()}, "not base64!", id, "j")
	assert.ErrorContains(t, err, "join key")

	tok, _ := NewTokenStore().Mint(time.Minute, 1)

	// a member that answers with a malformed challenge
	go func() {
		var h hello
		_ = readFrame(c2, &h)
		_ = writeFrame(c2, challenge{Nonce: []byte{1}})
		_ = c2.Close()
	}()
	_, _, err = Join(identified{c1, other.Public()}, tok, id, "j")
	assert.ErrorContains(t, err, "malformed challenge")
}

// On an authenticated connection the identities in the messages must be the peer's.
func Test_identityBinding(t *testing.T) {
	srv, _ := member(t)
	tok, err := srv.Tokens.Mint(time.Minute, 1)
	require.NoError(t, err)
	joiner, other := newID(t), newID(t)

	// server side: hello claims joiner but the connection belongs to other
	c1 := pipeTo(t, srv, other.Public())
	setDeadline(c1)
	tid := idOf(mustKey(t, tok))
	require.NoError(t, writeFrame(c1, hello{Version: Version, TokenID: tid[:], Identity: joiner.Public(), DH: joiner.DHPublic(), Nonce: make([]byte, nonceLen), Name: "j"}))
	var c challenge
	assert.Error(t, readFrame(c1, &c), "server hangs up on a mismatch")
	assert.Equal(t, 1, srv.Tokens.Pending())

	// joiner side: the challenge claims the member but the connection belongs to other
	_, _, err = Join(identified{pipeTo(t, srv, joiner.Public()), other.Public()}, tok, joiner, "j")
	assert.ErrorContains(t, err, "does not match the connection")

	// and with matching identities the exchange succeeds
	w, memberID, err := Join(pipeTo(t, srv, joiner.Public()), tok, joiner, "j")
	require.NoError(t, err)
	assert.Equal(t, srv.Identity.Public(), memberID)
	assert.Equal(t, joiner.Public(), w.Admission.Identity)
}

func mustKey(t *testing.T, tok string) []byte {
	t.Helper()
	key, err := DecodeToken(tok)
	require.NoError(t, err)
	return key
}

func Test_Join_rejectsForeignAdmission(t *testing.T) {
	// the member hands back an admission for someone else
	id := newID(t)
	set := trust.NewSet(id.Public())
	_, err := set.AddAdmission(trust.SelfAdmit(id, "root", time.Now()))
	require.NoError(t, err)
	srv := &Server{Identity: id, Tokens: NewTokenStore(), Root: id.Public(), GossipAddr: "x",
		Admit: func(trust.PublicKey, trust.DHKey, string) (trust.Admission, trust.Records, error) {
			other := newID(t)
			return trust.Admit(id, other.Public(), other.DHPublic(), "other", 2, time.Now()), set.Records(), nil
		}}
	tok, err := srv.Tokens.Mint(time.Minute, 1)
	require.NoError(t, err)
	_, _, err = join(t, srv, tok, newID(t), "j")
	assert.ErrorContains(t, err, "someone else")
}
