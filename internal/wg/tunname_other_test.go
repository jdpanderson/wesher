//go:build !darwin

package wg

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// useTempNameDir does nothing where the interface keeps the agent's name.
func useTempNameDir(*testing.T) {}

func Test_tunName_other(t *testing.T) {
	assert.Equal(t, "wgoverlay", tunName("wgoverlay"), "the interface carries the agent's name")
	assert.NoError(t, published("wgoverlay", "wgoverlay"))
	assert.NoError(t, unpublished("wgoverlay"))
}
