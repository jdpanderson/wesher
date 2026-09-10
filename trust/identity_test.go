package trust

import (
	"crypto/ed25519"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_IdentityFromSeed_badLength(t *testing.T) {
	_, err := IdentityFromSeed([]byte("short"))
	assert.ErrorContains(t, err, "seed must be 32 bytes")
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
	assert.Error(t, err)

	other := newID(t)
	ss, err := id.SharedSecret(other.DHPublic())
	require.NoError(t, err)
	assert.False(t, allZero(ss))
	assert.True(t, allZero(nil))
	assert.True(t, allZero([]byte{0, 0}))
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
