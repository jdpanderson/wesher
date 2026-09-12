package trust

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Set_AddRevocation(t *testing.T) {
	root, a, b, stranger, set := cluster(t)
	_, err := set.AddRevocation(Revoke(a, root.Public(), t0))
	assert.ErrorContains(t, err, "root cannot be revoked")

	rev := Revoke(a, b.Public(), t0.Add(time.Hour))
	rev.IssuedAt++
	_, err = set.AddRevocation(rev)
	assert.ErrorContains(t, err, "signature")

	ok, err := set.AddRevocation(Revoke(a, b.Public(), t0.Add(time.Hour)))
	require.NoError(t, err)
	assert.True(t, ok)
	ok, err = set.AddRevocation(Revoke(root, b.Public(), t0.Add(2*time.Hour)))
	require.NoError(t, err)
	assert.False(t, ok, "the first revocation stands")

	// a stranger's revocation is stored but carries no weight
	ok, err = set.AddRevocation(Revoke(stranger, a.Public(), t0))
	require.NoError(t, err)
	assert.True(t, ok)
	assert.True(t, set.Valid(a.Public()))
}

func Test_Set_Merge_skipsBadRecords(t *testing.T) {
	root, a, _, _, set := cluster(t)
	c := newID(t)
	good := Admit(root, c.Public(), c.DHPublic(), "c", 4, t0)
	bad := Admit(root, c.Public(), c.DHPublic(), "c", 5, t0)
	bad.Name = "tampered"
	badRev := Revoke(a, root.Public(), t0)
	n := set.Merge(Records{Admissions: []Admission{bad, good}, Revocations: []Revocation{badRev}})
	assert.Equal(t, 1, n)
	assert.True(t, set.Valid(c.Public()))
}

func Test_Set_ByName(t *testing.T) {
	root, a, _, _, set := cluster(t)
	got, ok := set.ByName("a")
	require.True(t, ok)
	assert.Equal(t, a.Public(), got.Identity)
	got, ok = set.ByName("root")
	require.True(t, ok, "the root's own record is not special")
	assert.Equal(t, root.Public(), got.Identity)
	_, ok = set.ByName("nobody")
	assert.False(t, ok)

	// two valid members with one name: ambiguous
	twin := newID(t)
	_, err := set.AddAdmission(Admit(root, twin.Public(), twin.DHPublic(), "a", 9, t0))
	require.NoError(t, err)
	_, ok = set.ByName("a")
	assert.False(t, ok)

	// a revoked member's name no longer resolves
	_, err = set.AddRevocation(Revoke(root, twin.Public(), t0.Add(time.Hour)))
	require.NoError(t, err)
	got, ok = set.ByName("a")
	require.True(t, ok)
	assert.Equal(t, a.Public(), got.Identity)
}

func Test_Set_NameTaken(t *testing.T) {
	root, a, b, stranger, set := cluster(t)
	assert.True(t, set.NameTaken("a", PublicKey{}))
	assert.False(t, set.NameTaken("a", a.Public()), "a node may keep its own name")
	assert.False(t, set.NameTaken("nobody", PublicKey{}))
	assert.True(t, set.NameTaken("root", stranger.Public()))

	_, err := set.AddRevocation(Revoke(root, b.Public(), t0.Add(time.Hour)))
	require.NoError(t, err)
	assert.False(t, set.NameTaken("b", PublicKey{}), "a revoked member's name is free")
}
