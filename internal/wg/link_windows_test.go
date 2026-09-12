//go:build windows

package wg

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

func Test_windows_nextHop(t *testing.T) {
	assert.Equal(t, netip.IPv4Unspecified(), nextHop(netip.MustParsePrefix("10.0.0.1/32")))
	assert.Equal(t, netip.IPv6Unspecified(), nextHop(netip.MustParsePrefix("fd00::1/128")))
}

func Test_windows_managedRoutes(t *testing.T) {
	row := func(luid winipcfg.LUID, proto winipcfg.RouteProtocol, dst string) winipcfg.MibIPforwardRow2 {
		r := winipcfg.MibIPforwardRow2{InterfaceLUID: luid, Protocol: proto}
		require.NoError(t, r.DestinationPrefix.SetPrefix(netip.MustParsePrefix(dst)))
		return r
	}
	rows := []winipcfg.MibIPforwardRow2{
		row(7, winipcfg.RouteProtocolNetMgmt, "10.99.0.1/32"),
		row(7, winipcfg.RouteProtocolNetMgmt, "fd00:7::/64"),
		row(8, winipcfg.RouteProtocolNetMgmt, "10.99.0.2/32"), // another interface
		row(7, winipcfg.RouteProtocolLocal, "10.99.0.100/32"), // the stack's own
	}
	assert.Equal(t, []netip.Prefix{netip.MustParsePrefix("10.99.0.1/32"), netip.MustParsePrefix("fd00:7::/64")}, managedRoutes(rows, 7))
	assert.Empty(t, managedRoutes(rows, 9))
}

func Test_windows_winLinker_missingInterface(t *testing.T) {
	link := winLinker{}
	_, err := link.Addrs("nonexistent0")
	assert.Error(t, err)
	_, err = link.Routes("nonexistent0")
	assert.Error(t, err)
	assert.Error(t, link.AddRoute("nonexistent0", netip.MustParsePrefix("10.99.0.1/32")))
	assert.Error(t, link.Up("nonexistent0"))
	_, _, err = lookup("nonexistent0")
	assert.Error(t, err)
}
