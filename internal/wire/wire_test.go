package wire

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Canonical(t *testing.T) {
	assert.Equal(t, []byte("d\x00\x00\x00\x00\x02ab\x00\x00\x00\x00"), Canonical("d", []byte("ab"), nil))
	assert.Equal(t, []byte("d\x00"), Canonical("d"))
	assert.NotEqual(t, Canonical("d", []byte("ab"), []byte("c")), Canonical("d", []byte("a"), []byte("bc")), "boundaries are unambiguous")
	assert.NotEqual(t, Canonical("d", []byte("a")), Canonical("e", []byte("a")), "domain separation")
}
