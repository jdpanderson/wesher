// Package trust implements node identities, signed admission records and the
// validity rules that decide cluster membership. See docs/membership.md.
package trust

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
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
func (k *PublicKey) UnmarshalText(text []byte) error {
	b, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil {
		return fmt.Errorf("identity: %w", err)
	}
	if len(b) != len(k) {
		return fmt.Errorf("identity: want %d bytes, got %d", len(k), len(b))
	}
	copy(k[:], b)
	return nil
}

// ParsePublicKey parses the base64 form.
func ParsePublicKey(s string) (PublicKey, error) {
	var k PublicKey
	err := k.UnmarshalText([]byte(s))
	return k, err
}

// DHKey is an X25519 public key.
type DHKey [32]byte

// MarshalText implements encoding.TextMarshaler.
func (k DHKey) MarshalText() ([]byte, error) {
	return []byte(base64.StdEncoding.EncodeToString(k[:])), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (k *DHKey) UnmarshalText(text []byte) error {
	b, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil {
		return fmt.Errorf("dh key: %w", err)
	}
	if len(b) != len(k) {
		return fmt.Errorf("dh key: want %d bytes, got %d", len(k), len(b))
	}
	copy(k[:], b)
	return nil
}

// Identity is a node's long-lived key material, all derived from one seed.
type Identity struct {
	seed []byte
	sign ed25519.PrivateKey
	dh   *ecdh.PrivateKey
}

// NewIdentity generates a fresh random identity.
func NewIdentity() (*Identity, error) {
	seed := make([]byte, SeedLen)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("reading random source: %w", err)
	}
	return IdentityFromSeed(seed)
}

// IdentityFromSeed derives the signing and DH keys from a persisted seed.
func IdentityFromSeed(seed []byte) (*Identity, error) {
	if len(seed) != SeedLen {
		return nil, fmt.Errorf("identity seed must be %d bytes, got %d", SeedLen, len(seed))
	}
	dhSeed, err := hkdf.Key(sha256.New, seed, nil, "cheesecloth/dh/v1", 32)
	if err != nil {
		return nil, fmt.Errorf("deriving dh key: %w", err)
	}
	dh, err := ecdh.X25519().NewPrivateKey(dhSeed)
	if err != nil {
		return nil, fmt.Errorf("deriving dh key: %w", err)
	}
	return &Identity{
		seed: append([]byte(nil), seed...),
		sign: ed25519.NewKeyFromSeed(seed),
		dh:   dh,
	}, nil
}

// Seed returns the seed to persist. Treat it as a secret.
func (i *Identity) Seed() []byte { return append([]byte(nil), i.seed...) }

// Public is the identity's public key.
func (i *Identity) Public() PublicKey {
	var k PublicKey
	copy(k[:], i.sign.Public().(ed25519.PublicKey))
	return k
}

// DHPublic is the identity's X25519 public key.
func (i *Identity) DHPublic() DHKey {
	var k DHKey
	copy(k[:], i.dh.PublicKey().Bytes())
	return k
}

// Sign signs msg with the identity's signing key.
func (i *Identity) Sign(msg []byte) []byte { return ed25519.Sign(i.sign, msg) }

// Signer exposes the Ed25519 private key, for TLS certificates.
func (i *Identity) Signer() ed25519.PrivateKey { return i.sign }

// SharedSecret is the raw X25519 shared secret with peer. Callers must run it
// through a KDF before use.
func (i *Identity) SharedSecret(peer DHKey) ([]byte, error) {
	pub, err := ecdh.X25519().NewPublicKey(peer[:])
	if err != nil {
		return nil, fmt.Errorf("peer dh key: %w", err)
	}
	ss, err := i.dh.ECDH(pub)
	if err != nil {
		return nil, fmt.Errorf("x25519: %w", err)
	}
	if allZero(ss) {
		return nil, errors.New("x25519: low-order peer key")
	}
	return ss, nil
}

func allZero(b []byte) bool {
	var acc byte
	for _, x := range b {
		acc |= x
	}
	return acc == 0
}

// Verify checks an Ed25519 signature by identity over msg.
func Verify(identity PublicKey, msg, sig []byte) bool {
	return ed25519.Verify(ed25519.PublicKey(identity[:]), msg, sig)
}
