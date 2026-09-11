package wire

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Fields(t *testing.T) {
	assert.Equal(t, []byte("\x00\x00\x00\x02ab\x00\x00\x00\x00"), Fields([]byte("ab"), nil))
	assert.Empty(t, Fields())
	assert.NotEqual(t, Fields([]byte("ab"), []byte("c")), Fields([]byte("a"), []byte("bc")), "boundaries are unambiguous")
}

func Test_Canonical(t *testing.T) {
	assert.Equal(t, []byte("d\x00\x00\x00\x00\x02ab\x00\x00\x00\x00"), Canonical("d", []byte("ab"), nil))
	assert.NotEqual(t, Canonical("d", []byte("a")), Canonical("e", []byte("a")), "domain separation")
}
