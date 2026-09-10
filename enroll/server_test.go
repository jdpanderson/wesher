package enroll

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/jdpanderson/cheesecloth/trust"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Failure paths of the exchange; the successful and token-related paths are in enroll_test.go.

func Test_handle_malformedHello(t *testing.T) {
	_, _, addr := member(t)
	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	require.NoError(t, writeFrame(conn, hello{Version: Version + 1, TokenID: make([]byte, tokenIDLen), Nonce: make([]byte, nonceLen), Name: "j"}))
	var c challenge
	assert.Error(t, readFrame(conn, &c), "the member hangs up without a challenge")
}

func Test_handle_badProof(t *testing.T) {
	srv, _, addr := member(t)
	tok, err := srv.Tokens.Mint(time.Minute, 1)
	require.NoError(t, err)
	key, err := DecodeToken(tok)
	require.NoError(t, err)
	joiner := newID(t)

	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
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
	id := newID(t)
	ctx := context.Background()
	_, _, err := Join(ctx, "127.0.0.1:1", "not base64!", id, "j")
	assert.ErrorContains(t, err, "join key")

	tok, _ := NewTokenStore().Mint(time.Minute, 1)
	_, _, err = Join(ctx, "127.0.0.1:1", tok, id, "j")
	assert.Error(t, err, "nothing listening")

	// a member that answers with a malformed challenge
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()
	go func() {
		conn, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		var h hello
		_ = readFrame(conn, &h)
		_ = writeFrame(conn, challenge{Nonce: []byte{1}})
	}()
	_, _, err = Join(ctx, ln.Addr().String(), tok, id, "j")
	assert.ErrorContains(t, err, "malformed challenge")
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
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()
	go srv.Serve(ln)
	tok, err := srv.Tokens.Mint(time.Minute, 1)
	require.NoError(t, err)
	_, _, err = Join(context.Background(), ln.Addr().String(), tok, newID(t), "j")
	assert.ErrorContains(t, err, "someone else")
}
