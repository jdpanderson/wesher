package main

import (
	"net"
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
			"overlay mask not multiple of 8",
			AgentCmd{OverlayNet: netip.MustParsePrefix("10.0.0.0/20"), MTU: 1420},
			"unsupported overlay network size",
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

func testAddrs(t *testing.T, cidrs ...string) []net.Addr {
	t.Helper()
	addrs := make([]net.Addr, 0, len(cidrs))
	for _, c := range cidrs { // like iface.Addrs(): host IP with the interface mask
		ip, n, err := net.ParseCIDR(c)
		require.NoError(t, err)
		addrs = append(addrs, &net.IPNet{IP: ip, Mask: n.Mask})
	}
	return addrs
}

func Test_pickAdvertiseAddr(t *testing.T) {
	v4 := netip.IPv4Unspecified()
	v6 := netip.IPv6Unspecified()
	mixed := testAddrs(t,
		"fe80::1/64",      // IPv6 link-local: never
		"169.254.1.2/16",  // IPv4 link-local: never
		"192.168.7.7/24",  // private IPv4
		"100.64.0.9/10",   // shared address space: private
		"fd00::7/64",      // IPv6 ULA: private
		"198.51.100.7/24", // public IPv4
		"2001:db8::7/64",  // public IPv6
	)

	got, ok := pickAdvertiseAddr(v4, mixed)
	require.True(t, ok)
	assert.Equal(t, "198.51.100.7", got.String(), "public IPv4 wins over private")

	got, ok = pickAdvertiseAddr(v6, mixed)
	require.True(t, ok)
	assert.Equal(t, "2001:db8::7", got.String(), "public IPv6 wins over ULA")

	got, ok = pickAdvertiseAddr(v4, testAddrs(t, "fe80::1/64", "169.254.1.2/16", "10.1.2.3/24"))
	require.True(t, ok)
	assert.Equal(t, "10.1.2.3", got.String(), "private is fine when nothing public exists")

	got, ok = pickAdvertiseAddr(v6, testAddrs(t, "fe80::1/64", "fd00::7/64"))
	require.True(t, ok)
	assert.Equal(t, "fd00::7", got.String())

	_, ok = pickAdvertiseAddr(v6, testAddrs(t, "192.168.7.7/24", "fe80::1/64"))
	assert.False(t, ok, "no usable IPv6")

	_, ok = pickAdvertiseAddr(v4, testAddrs(t, "169.254.1.2/16", "127.0.0.1/8"))
	assert.False(t, ok, "link-local and loopback never qualify")
}

func Test_firstAddr_unmaps(t *testing.T) {
	mapped := &net.IPNet{IP: net.ParseIP("198.51.100.7"), Mask: net.CIDRMask(120, 128)} // 16-byte form of a v4 address
	got, ok := firstAddr([]net.Addr{mapped, &net.IPAddr{IP: net.ParseIP("203.0.113.1")}}, func(netip.Addr) bool { return true })
	require.True(t, ok)
	assert.True(t, got.Is4())
	assert.Equal(t, "198.51.100.7", got.String())
}

func Test_AgentCmd_advertiseAddr(t *testing.T) {
	cmd := validCmd()
	cmd.BindAddr = netip.MustParseAddr("192.0.2.1")
	got, err := cmd.advertiseAddr()
	require.NoError(t, err)
	assert.Equal(t, cmd.BindAddr, got, "a specific bind address is advertised as is")

	cmd.BindAddr = netip.IPv4Unspecified()
	if _, ok := pickAdvertiseAddr(cmd.BindAddr, upInterfaceAddrs(cmd.Interface)); !ok {
		_, err = cmd.advertiseAddr()
		assert.ErrorContains(t, err, "no IPv4 address found")
		t.Skip("host has no non-loopback IPv4 address; wildcard resolution not testable here")
	}
	got, err = cmd.advertiseAddr()
	require.NoError(t, err)
	assert.True(t, got.Is4() && !got.IsUnspecified() && !got.IsLoopback(), "got %s", got)
}

func Test_AgentCmd_Validate_validKey(t *testing.T) {
	cmd := validCmd()
	cmd.ClusterKey = key("abcdefghijklmnopqrstuvwxyzABCDEF")
	cmd.BindAddr = netip.MustParseAddr("127.0.0.1")
	require.NoError(t, cmd.Validate())
}
