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

func Test_firstIPv4(t *testing.T) {
	ipnet := func(s string) net.Addr { // like iface.Addrs(): host IP with the interface mask
		ip, n, err := net.ParseCIDR(s)
		require.NoError(t, err)
		return &net.IPNet{IP: ip, Mask: n.Mask}
	}
	addrs := []net.Addr{
		ipnet("fe80::1/64"),      // IPv6 link-local
		ipnet("169.254.1.2/16"),  // IPv4 link-local
		ipnet("2001:db8::1/64"),  // IPv6 global
		ipnet("10.1.2.3/24"),     // private IPv4
		ipnet("100.64.0.9/10"),   // shared address space
		ipnet("198.51.100.7/24"), // public IPv4 (TEST-NET-2)
		&net.IPAddr{IP: net.ParseIP("203.0.113.1")},
	}

	got, ok := firstIPv4(addrs, netip.Addr.IsGlobalUnicast)
	require.True(t, ok)
	assert.Equal(t, "10.1.2.3", got.String(), "first global unicast IPv4 wins over link-local and IPv6")

	got, ok = firstIPv4(addrs, isPublic)
	require.True(t, ok)
	assert.Equal(t, "198.51.100.7", got.String(), "private and shared space are not public")

	_, ok = firstIPv4([]net.Addr{ipnet("fe80::1/64"), ipnet("2001:db8::1/64")}, func(netip.Addr) bool { return true })
	assert.False(t, ok, "IPv6-only yields nothing")

	got, ok = firstIPv4([]net.Addr{ipnet("127.0.0.1/8")}, func(netip.Addr) bool { return true })
	require.True(t, ok)
	assert.Equal(t, "127.0.0.1", got.String())
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
