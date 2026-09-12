package trust

import (
	"crypto/ed25519"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Identity_deterministicFromSeed(t *testing.T) {
	a := newID(t)
	b, err := IdentityFromSeed(a.Seed())
	require.NoError(t, err)
	assert.Equal(t, a.Public(), b.Public())
	assert.Equal(t, a.DHPublic(), b.DHPublic())

	_, err = IdentityFromSeed([]byte("short"))
	assert.ErrorContains(t, err, "seed must be 32 bytes")

	c := newID(t)
	assert.NotEqual(t, a.Public(), c.Public())
}

func Test_Identity_signAndShare(t *testing.T) {
	a, b := newID(t), newID(t)
	msg := []byte("hello")
	assert.True(t, Verify(a.Public(), msg, a.Sign(msg)))
	assert.False(t, Verify(b.Public(), msg, a.Sign(msg)))

	ab, err := a.SharedSecret(b.DHPublic())
	require.NoError(t, err)
	ba, err := b.SharedSecret(a.DHPublic())
	require.NoError(t, err)
	assert.Equal(t, ab, ba)
	assert.Len(t, ab, 32)
}

func Test_Identity_Signer(t *testing.T) {
	id := newID(t)
	sig := ed25519.Sign(id.Signer(), []byte("msg"))
	assert.True(t, Verify(id.Public(), []byte("msg"), sig), "the TLS signer is the identity key")
	assert.Equal(t, id.Seed(), id.Signer().Seed())
}

func Test_Identity_SharedSecret_badPeer(t *testing.T) {
	id := newID(t)
	_, err := id.SharedSecret(DHKey{}) // the all-zero point is low order
	assert.ErrorContains(t, err, "low order")

	other := newID(t)
	ss, err := id.SharedSecret(other.DHPublic())
	require.NoError(t, err)
	assert.NotEqual(t, make([]byte, 32), ss)
}

func Test_PublicKey_text(t *testing.T) {
	id := newID(t)
	s := id.Public().String()
	back, err := ParsePublicKey(s)
	require.NoError(t, err)
	assert.Equal(t, id.Public(), back)
	assert.Len(t, id.Public().Short(), 8)
	_, err = ParsePublicKey("not base64!")
	assert.Error(t, err)
	_, err = ParsePublicKey("YWJj")
	assert.ErrorContains(t, err, "want 32 bytes")
}

func Test_DHKey_text(t *testing.T) {
	id := newID(t)
	text, err := id.DHPublic().MarshalText()
	require.NoError(t, err)
	var k DHKey
	require.NoError(t, k.UnmarshalText(text))
	assert.Equal(t, id.DHPublic(), k)

	assert.ErrorContains(t, k.UnmarshalText([]byte("not base64!")), "dh key")
	assert.ErrorContains(t, k.UnmarshalText([]byte("YWJj")), "want 32 bytes")
}
