package cli

import (
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testOverlay = netip.MustParsePrefix("10.0.0.0/8")

// validCmd returns an AgentCmd with the flag defaults that Validate requires.
func validCmd() AgentCmd {
	return AgentCmd{OverlayNet: testOverlay, MTU: 1420, BindAddr: netip.IPv4Unspecified()}
}

func Test_AgentCmd_Validate_errors(t *testing.T) {
	tests := []struct {
		name    string
		cmd     AgentCmd
		wantErr string
	}{
		{
			"overlay too small",
			AgentCmd{OverlayNet: netip.MustParsePrefix("10.0.0.0/31"), MTU: 1420},
			"no room for two nodes",
		},
		{
			"mtu too small",
			AgentCmd{OverlayNet: testOverlay, MTU: 500},
			"unsupported MTU",
		},
		{
			"keepalive not whole seconds",
			AgentCmd{OverlayNet: testOverlay, MTU: 1420, PersistentKeepalive: 1500 * time.Millisecond},
			"unsupported persistent keepalive",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cmd.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func Test_AgentCmd_Validate_joinKey(t *testing.T) {
	cmd := validCmd()
	cmd.JoinKey = "token"
	assert.ErrorContains(t, cmd.Validate(), "needs --join")
	cmd.Join = []string{"member"}
	require.NoError(t, cmd.Validate())
	cmd.Init = true
	assert.ErrorContains(t, cmd.Validate(), "cannot be combined")
}
