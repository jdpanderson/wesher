package enroll

import (
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_hkdfExpand(t *testing.T) {
	a := hkdfExpand(sha256.New, []byte("secret"), []byte("salt"), "info", 48)
	assert.Len(t, a, 48)
	assert.Equal(t, a, hkdfExpand(sha256.New, []byte("secret"), []byte("salt"), "info", 48), "deterministic")
	assert.NotEqual(t, a, hkdfExpand(sha256.New, []byte("secret"), []byte("other"), "info", 48))
	assert.NotEqual(t, a, hkdfExpand(sha256.New, []byte("secret"), []byte("salt"), "other", 48))
	assert.Panics(t, func() { hkdfExpand(sha256.New, []byte("secret"), nil, "info", 255*sha256.Size+1) }, "more than HKDF can produce")
}
