package trust

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Admission_VerifySignature(t *testing.T) {
	root, a := newID(t), newID(t)
	adm := Admit(root, a.Public(), a.DHPublic(), "a", 2, t0)
	require.NoError(t, adm.VerifySignature())

	for name, mutate := range map[string]func(*Admission){
		"name":      func(x *Admission) { x.Name = "b" },
		"host":      func(x *Admission) { x.Host = 3 },
		"identity":  func(x *Admission) { x.Identity = root.Public() },
		"dh":        func(x *Admission) { x.DHKey = root.DHPublic() },
		"issued":    func(x *Admission) { x.IssuedAt++ },
		"admitter":  func(x *Admission) { x.Admitter = a.Public() },
		"signature": func(x *Admission) { x.Signature[0] ^= 1 },
	} {
		x := adm
		x.Signature = append([]byte(nil), adm.Signature...)
		mutate(&x)
		assert.Error(t, x.VerifySignature(), name)
	}
	x := adm
	x.Name = ""
	assert.ErrorContains(t, x.VerifySignature(), "without a name")
	x = adm
	x.Host = 0
	assert.ErrorContains(t, x.VerifySignature(), "without an overlay slot")
}

func Test_Revocation_VerifySignature(t *testing.T) {
	root, a := newID(t), newID(t)
	rev := Revoke(root, a.Public(), t0)
	require.NoError(t, rev.VerifySignature())
	x := rev
	x.IssuedAt++
	assert.ErrorContains(t, x.VerifySignature(), "signature")
	x = rev
	x.Revoker = a.Public()
	assert.Error(t, x.VerifySignature())
}

func Test_canonical(t *testing.T) {
	assert.Equal(t, []byte("d\x00\x00\x00\x00\x02ab\x00\x00\x00\x00"), canonical("d", []byte("ab"), nil))
	assert.NotEqual(t, canonical("d", []byte("a")), canonical("e", []byte("a")), "domain separation")
}
