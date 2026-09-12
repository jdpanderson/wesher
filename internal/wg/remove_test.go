package wg

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Removing what is not there is how a leave finds a node whose agent shut
// down cleanly, and must not be an error.
func Test_Remove_missingInterface(t *testing.T) {
	assert.NoError(t, Remove("wgnosuchiface"))
}
