package main

import (
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testOverlay = netip.MustParsePrefix("10.0.0.0/8")

func Test_AgentCmd_Validate_errors(t *testing.T) {
	tests := []struct {
		name    string
		cmd     AgentCmd
		wantErr string
	}{
		{
			"overlay mask not multiple of 8",
			AgentCmd{OverlayNet: netip.MustParsePrefix("10.0.0.0/20")},
			"unsupported overlay network size",
		},
		{
			"bind addr and iface both set",
			AgentCmd{OverlayNet: testOverlay, BindAddr: "127.0.0.1", BindIface: "lo"},
			"both bind address and bind interface",
		},
		{
			"bind iface missing",
			AgentCmd{OverlayNet: testOverlay, BindIface: "nonexistent0"},
			"getting interface by name",
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

func Test_AgentCmd_Validate_bindIface(t *testing.T) {
	cmd := AgentCmd{OverlayNet: testOverlay, BindIface: "lo"}
	require.NoError(t, cmd.Validate())
	assert.Equal(t, "127.0.0.1", cmd.BindAddr)
}

func Test_AgentCmd_Validate_bindAddrExplicit(t *testing.T) {
	cmd := AgentCmd{OverlayNet: testOverlay, BindAddr: "192.0.2.1"}
	require.NoError(t, cmd.Validate())
	assert.Equal(t, "192.0.2.1", cmd.BindAddr)
}

func Test_AgentCmd_Validate_bindAddrAutodetect(t *testing.T) {
	cmd := AgentCmd{OverlayNet: testOverlay}
	require.NoError(t, cmd.Validate())
	assert.NotNil(t, net.ParseIP(cmd.BindAddr), "expected an IP, got %q", cmd.BindAddr)
}

func Test_AgentCmd_Validate_validKey(t *testing.T) {
	cmd := AgentCmd{
		ClusterKey: key("abcdefghijklmnopqrstuvwxyzABCDEF"),
		OverlayNet: testOverlay,
		BindAddr:   "127.0.0.1",
	}
	require.NoError(t, cmd.Validate())
}
