// Package trust implements node identities, signed admission records and the
// validity rules that decide cluster membership. See docs/membership.md.
package trust

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// SeedLen is the length of an identity seed in bytes.
const SeedLen = 32

// PublicKey is a node identity: its Ed25519 public key.
type PublicKey [ed25519.PublicKeySize]byte

// String is the base64 form used in files and on the wire.
func (k PublicKey) String() string { return base64.StdEncoding.EncodeToString(k[:]) }

// Short is a fingerprint for humans: the first 8 base64 characters.
func (k PublicKey) Short() string { return k.String()[:8] }

// MarshalText implements encoding.TextMarshaler.
func (k PublicKey) MarshalText() ([]byte, error) { return []byte(k.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (k *PublicKey) UnmarshalText(text []byte) error { return decodeKey("identity", text, k[:]) }

// decodeKey fills dst from the base64 text of a key, naming what in errors.
func decodeKey(what string, text, dst []byte) error {
	b, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	if len(b) != len(dst) {
		return fmt.Errorf("%s: want %d bytes, got %d", what, len(dst), len(b))
	}
	copy(dst, b)
	return nil
}

// ParsePublicKey parses the base64 form.
func ParsePublicKey(s string) (PublicKey, error) {
	var k PublicKey
	err := k.UnmarshalText([]byte(s))
	return k, err
}

// Identity is a node's long-lived key material, derived from one seed.
type Identity struct {
	seed []byte
	sign ed25519.PrivateKey
}

// NewIdentity generates a fresh random identity.
func NewIdentity() (*Identity, error) {
	seed := make([]byte, SeedLen)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("reading random source: %w", err)
	}
	return IdentityFromSeed(seed)
}

// IdentityFromSeed derives the signing key from a persisted seed.
func IdentityFromSeed(seed []byte) (*Identity, error) {
	if len(seed) != SeedLen {
		return nil, fmt.Errorf("identity seed must be %d bytes, got %d", SeedLen, len(seed))
	}
	return &Identity{seed: append([]byte(nil), seed...), sign: ed25519.NewKeyFromSeed(seed)}, nil
}

// Seed returns the seed to persist. Treat it as a secret.
func (i *Identity) Seed() []byte { return append([]byte(nil), i.seed...) }

// Public is the identity's public key.
func (i *Identity) Public() PublicKey {
	var k PublicKey
	copy(k[:], i.sign.Public().(ed25519.PublicKey))
	return k
}

// Sign signs msg with the identity's signing key.
func (i *Identity) Sign(msg []byte) []byte { return ed25519.Sign(i.sign, msg) }

// Signer exposes the Ed25519 private key, for TLS certificates.
func (i *Identity) Signer() ed25519.PrivateKey { return i.sign }

// Verify checks an Ed25519 signature by identity over msg.
func Verify(identity PublicKey, msg, sig []byte) bool {
	return ed25519.Verify(ed25519.PublicKey(identity[:]), msg, sig)
}
