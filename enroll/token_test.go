package enroll

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_token_codec(t *testing.T) {
	key := make([]byte, tokenLen)
	for i := range key {
		key[i] = byte(i)
	}
	got, err := DecodeToken(EncodeToken(key))
	require.NoError(t, err)
	assert.Equal(t, key, got)

	_, err = DecodeToken("not a token!")
	assert.ErrorContains(t, err, "join key")
	upper, err := DecodeToken(strings.ToUpper(EncodeToken(key)))
	require.NoError(t, err)
	assert.Equal(t, key, upper, "case and surrounding whitespace do not matter")
	_, err = DecodeToken(" " + EncodeToken(key) + "\n")
	require.NoError(t, err)
	_, err = DecodeToken(EncodeToken(key[:5]))
	assert.ErrorContains(t, err, "want 32 bytes")

	assert.NotEqual(t, idOf(key), idOf(append([]byte{1}, key[1:]...)), "the public id depends on the whole key")
}

// A token is pasted after --join-key on a command line, so it must never look like a flag.
func Test_token_isPlainWord(t *testing.T) {
	s := NewTokenStore()
	for i := 0; i < 200; i++ {
		tok, err := s.Mint(time.Minute, 1)
		require.NoError(t, err)
		assert.Regexp(t, `^[a-z2-7]{52}$`, tok)
	}
}

func Test_TokenStore_expiry(t *testing.T) {
	s := NewTokenStore()
	now := time.Unix(1_700_000_000, 0)
	s.now = func() time.Time { return now }

	tok, err := s.Mint(time.Minute, 2)
	require.NoError(t, err)
	key, err := DecodeToken(tok)
	require.NoError(t, err)
	assert.Equal(t, 1, s.Pending())

	now = now.Add(59 * time.Second)
	_, ok := s.lookup(idOf(key))
	assert.True(t, ok)
	now = now.Add(time.Second)
	_, ok = s.lookup(idOf(key))
	assert.False(t, ok, "expired at exactly ttl")
	assert.Equal(t, 0, s.Pending())
}

func Test_TokenStore_uses(t *testing.T) {
	s := NewTokenStore()
	tok, err := s.Mint(time.Minute, 2)
	require.NoError(t, err)
	key, _ := DecodeToken(tok)
	id := idOf(key)

	s.consume(tokenID{9}) // unknown: no-op
	s.consume(id)
	_, ok := s.lookup(id)
	assert.True(t, ok, "one use left")
	s.consume(id)
	_, ok = s.lookup(id)
	assert.False(t, ok)
}
