package trust

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var t0 = time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)

func newID(t *testing.T) *Identity {
	t.Helper()
	id, err := NewIdentity()
	require.NoError(t, err)
	return id
}

// cluster builds root -> a -> b, and an unrelated stranger.
func cluster(t *testing.T) (root, a, b, stranger *Identity, set *Set) {
	t.Helper()
	root, a, b, stranger = newID(t), newID(t), newID(t), newID(t)
	set = NewSet(root.Public())
	for _, adm := range []Admission{
		SelfAdmit(root, "root", t0),
		Admit(root, a.Public(), a.DHPublic(), "a", 2, t0.Add(time.Minute)),
		Admit(a, b.Public(), b.DHPublic(), "b", 3, t0.Add(2*time.Minute)),
	} {
		ok, err := set.AddAdmission(adm)
		require.NoError(t, err)
		require.True(t, ok)
	}
	return
}
