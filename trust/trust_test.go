package trust

import (
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var t0 = time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)

func newID(t *testing.T) *Identity {
	t.Helper()
	id, err := NewIdentity()
	require.NoError(t, err)
	return id
}

func Test_Identity_deterministicFromSeed(t *testing.T) {
	a := newID(t)
	b, err := IdentityFromSeed(a.Seed())
	require.NoError(t, err)
	assert.Equal(t, a.Public(), b.Public())
	assert.Equal(t, a.DHPublic(), b.DHPublic())

	_, err = IdentityFromSeed([]byte("short"))
	assert.Error(t, err)

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

	_, err = a.SharedSecret(DHKey{}) // all-zero point is low order
	assert.Error(t, err)
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

// cluster builds root -> a -> b, and an unrelated stranger.
func cluster(t *testing.T) (root, a, b, stranger *Identity, set *Set) {
	t.Helper()
	root, a, b, stranger = newID(t), newID(t), newID(t), newID(t)
	set = NewSet(root.Public())
	for _, adm := range []Admission{
		SelfAdmit(root, "root", t0),
		Admit(root, a.Public(), a.DHPublic(), "a", t0.Add(time.Minute)),
		Admit(a, b.Public(), b.DHPublic(), "b", t0.Add(2*time.Minute)),
	} {
		ok, err := set.AddAdmission(adm)
		require.NoError(t, err)
		require.True(t, ok)
	}
	return
}

func Test_Set_validity(t *testing.T) {
	root, a, b, stranger, set := cluster(t)
	assert.True(t, set.Valid(root.Public()))
	assert.True(t, set.Valid(a.Public()))
	assert.True(t, set.Valid(b.Public()), "admitted by a valid non-root member")
	assert.False(t, set.Valid(stranger.Public()))

	// a stranger admitting itself is not a root
	_, err := set.AddAdmission(SelfAdmit(stranger, "x", t0))
	assert.ErrorIs(t, err, ErrUntrustedRoot)

	// a stranger's admission of someone else is stored (signature is fine) but confers nothing
	c := newID(t)
	ok, err := set.AddAdmission(Admit(stranger, c.Public(), c.DHPublic(), "c", t0))
	require.NoError(t, err)
	assert.True(t, ok)
	assert.False(t, set.Valid(c.Public()), "chain does not reach the root")

	// tampering breaks the signature
	adm := Admit(root, c.Public(), c.DHPublic(), "c", t0)
	adm.Name = "evil"
	_, err = set.AddAdmission(adm)
	assert.ErrorContains(t, err, "signature")

	dh, err := set.DHKeyOf(b.Public())
	require.NoError(t, err)
	assert.Equal(t, b.DHPublic(), dh)
	_, err = set.DHKeyOf(stranger.Public())
	assert.Error(t, err)

	names := []string{}
	for _, m := range set.Members() {
		names = append(names, m.Name)
	}
	assert.Equal(t, []string{"a", "b", "root"}, names)
	got, ok := set.ByName("b")
	assert.True(t, ok)
	assert.Equal(t, b.Public(), got.Identity)
	_, ok = set.ByName("nobody")
	assert.False(t, ok)
}

func Test_Set_revocation(t *testing.T) {
	t.Run("by a non-member has no effect", func(t *testing.T) {
		_, a, _, stranger, set := cluster(t)
		ok, err := set.AddRevocation(Revoke(stranger, a.Public(), t0.Add(3*time.Minute)))
		require.NoError(t, err) // the signature is fine; the record is simply ineffective
		assert.True(t, ok)
		assert.True(t, set.Valid(a.Public()))
	})

	t.Run("by a member removes the target only", func(t *testing.T) {
		_, a, b, _, set := cluster(t)
		ok, err := set.AddRevocation(Revoke(a, b.Public(), t0.Add(3*time.Minute)))
		require.NoError(t, err)
		assert.True(t, ok)
		assert.False(t, set.Valid(b.Public()))
		assert.True(t, set.Valid(a.Public()))
	})

	t.Run("does not cascade to earlier admissions", func(t *testing.T) {
		root, a, b, _, set := cluster(t)
		_, err := set.AddRevocation(Revoke(root, a.Public(), t0.Add(3*time.Minute)))
		require.NoError(t, err)
		assert.False(t, set.Valid(a.Public()))
		assert.True(t, set.Valid(b.Public()), "b was admitted while a was still a member")

		c := newID(t)
		_, err = set.AddAdmission(Admit(a, c.Public(), c.DHPublic(), "c", t0.Add(4*time.Minute)))
		require.NoError(t, err)
		assert.False(t, set.Valid(c.Public()), "admitted by a after a's revocation")
	})

	t.Run("root cannot be revoked", func(t *testing.T) {
		root, a, _, _, set := cluster(t)
		_, err := set.AddRevocation(Revoke(a, root.Public(), t0))
		assert.ErrorContains(t, err, "root cannot be revoked")
	})
}

func Test_Set_mergeAndRoundTrip(t *testing.T) {
	root, a, b, _, set := cluster(t)
	rs := set.Records()
	require.Len(t, rs.Admissions, 3)

	data, err := json.Marshal(rs)
	require.NoError(t, err)
	var back Records
	require.NoError(t, json.Unmarshal(data, &back))

	// merging into a fresh set in any order yields the same validity
	fresh := NewSet(root.Public())
	back.Admissions[0], back.Admissions[2] = back.Admissions[2], back.Admissions[0]
	assert.Equal(t, 3, fresh.Merge(back))
	assert.Equal(t, 0, fresh.Merge(back), "idempotent")
	for _, id := range []PublicKey{root.Public(), a.Public(), b.Public()} {
		assert.True(t, fresh.Valid(id))
	}

	// a set pinned to a different root trusts none of it
	other := NewSet(newID(t).Public())
	other.Merge(back)
	assert.False(t, other.Valid(a.Public()))
	assert.False(t, other.Valid(root.Public()))
}

func Test_Set_newerAdmissionReplaces(t *testing.T) {
	root, a, _, _, set := cluster(t)
	fresh := newID(t) // a re-enrolled with a new DH key but same identity? identity is the key; simulate new name
	_ = fresh
	older := Admit(root, a.Public(), a.DHPublic(), "a-old", t0)
	ok, err := set.AddAdmission(older)
	require.NoError(t, err)
	assert.False(t, ok, "older record does not replace")
	newer := Admit(root, a.Public(), a.DHPublic(), "a-new", t0.Add(time.Hour))
	ok, err = set.AddAdmission(newer)
	require.NoError(t, err)
	assert.True(t, ok)
	got, _ := set.Lookup(a.Public())
	assert.Equal(t, "a-new", got.Name)
}

func Test_MetaDigest(t *testing.T) {
	id := newID(t)
	d := MetaDigest("node", netip.MustParseAddr("10.0.0.1"), "wgkey")
	sig := id.Sign(d)
	assert.True(t, Verify(id.Public(), d, sig))
	assert.False(t, Verify(id.Public(), MetaDigest("node", netip.MustParseAddr("10.0.0.2"), "wgkey"), sig))
	assert.False(t, Verify(id.Public(), MetaDigest("other", netip.MustParseAddr("10.0.0.1"), "wgkey"), sig))
	// length-prefixing: moving bytes between fields changes the digest
	assert.NotEqual(t, canonical("d", []byte("ab"), []byte("c")), canonical("d", []byte("a"), []byte("bc")))
}
