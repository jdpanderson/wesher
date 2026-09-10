package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_StatusCmd_Run_missingInterface(t *testing.T) {
	// the interface cannot exist: either wireguard is unreachable or the device is unknown
	cmd := &StatusCmd{Interface: "cheesecloth-test-absent0"}
	assert.Error(t, cmd.Run())
}
