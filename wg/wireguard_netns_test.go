package wg

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/jdpanderson/cheesecloth/overlay"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const testPrefix = "10.99.0.0/16"

// enterTestNetns runs the rest of the test in a fresh network namespace.
// Skips without CAP_NET_ADMIN; `unshare -r go test ./...` or root provides it.
func enterTestNetns(t *testing.T) {
	t.Helper()
	runtime.LockOSThread()
	orig, err := netns.Get()
	require.NoError(t, err)
	ns, err := netns.New()
	if errors.Is(err, os.ErrPermission) {
		runtime.UnlockOSThread()
		t.Skip("needs CAP_NET_ADMIN (run under `unshare -r` or as root)")
	}
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = netns.Set(orig)
		_ = ns.Close()
		_ = orig.Close()
		runtime.UnlockOSThread()
	})
}

// testConfig uses a non-default MTU so the test proves it is applied.
func testConfig() Config {
	return Config{
		Interface: "wgtest0", Port: 51820, OverlayNet: netip.MustParsePrefix(testPrefix),
		OverlayAddr: netip.MustParseAddr("10.99.0.100"), MTU: 1400, PersistentKeepalive: 25 * time.Second,
	}
}

func testPeer(t *testing.T, name, addr, overlayAddr string) overlay.Node {
	t.Helper()
	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	n := overlay.Node{Name: name, Addr: net.ParseIP(addr)}
	n.OverlayAddr = netip.MustParseAddr(overlayAddr)
	n.PubKey = key.PublicKey().String()
	return n
}

func Test_New(t *testing.T) {
	enterTestNetns(t)
	s, err := New(testConfig())
	require.NoError(t, err)
	assert.Equal(t, s.privKey.PublicKey(), s.PubKey)
	assert.True(t, netip.MustParsePrefix(testPrefix).Contains(s.OverlayAddr))
}

func Test_State_SetUpInterface_and_Down(t *testing.T) {
	enterTestNetns(t)
	s, err := New(testConfig())
	require.NoError(t, err)

	p1 := testPeer(t, "p1", "192.0.2.1", "10.99.0.1")
	p1.AllowedIPs = []netip.Prefix{netip.MustParsePrefix("192.168.7.0/24")}
	p2 := testPeer(t, "p2", "192.0.2.2", "10.99.0.2")
	require.NoError(t, s.SetUpInterface([]overlay.Node{p1, p2}))

	link, err := netlink.LinkByName("wgtest0")
	require.NoError(t, err)
	assert.Equal(t, "wireguard", link.Type())
	assert.Equal(t, 1400, link.Attrs().MTU)
	assert.NotZero(t, link.Attrs().Flags&net.FlagUp)

	addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	require.NoError(t, err)
	require.Len(t, addrs, 1)
	assert.Equal(t, s.OverlayAddr.String()+"/32", addrs[0].IPNet.String())

	dev, err := s.client.Device("wgtest0")
	require.NoError(t, err)
	assert.Equal(t, s.PubKey, dev.PublicKey)
	assert.Equal(t, 51820, dev.ListenPort)
	require.Len(t, dev.Peers, 2)
	assert.Equal(t, "192.0.2.1:51820", dev.Peers[0].Endpoint.String())
	require.Len(t, dev.Peers[0].AllowedIPs, 2)
	assert.Equal(t, "10.99.0.1/32", dev.Peers[0].AllowedIPs[0].String())
	assert.Equal(t, "192.168.7.0/24", dev.Peers[0].AllowedIPs[1].String())
	assert.Equal(t, 25*time.Second, dev.Peers[0].PersistentKeepaliveInterval)

	routes, err := netlink.RouteList(link, netlink.FAMILY_V4)
	require.NoError(t, err)
	assert.Len(t, routes, 3, "two peer addresses and one advertised network")

	report, err := Status("wgtest0")
	require.NoError(t, err)
	assert.Equal(t, s.PubKey.String(), report.PublicKey)
	assert.Equal(t, []netip.Prefix{netip.PrefixFrom(s.OverlayAddr, 32)}, report.Addrs)
	require.Len(t, report.Peers, 2)
	assert.Equal(t, 25*time.Second, report.Peers[0].PersistentKeepalive)

	// idempotent: link and routes already exist
	require.NoError(t, s.SetUpInterface([]overlay.Node{p1, p2}))

	// peers and their routes are replaced, not accumulated
	require.NoError(t, s.SetUpInterface([]overlay.Node{p2}))
	dev, err = s.client.Device("wgtest0")
	require.NoError(t, err)
	assert.Len(t, dev.Peers, 1)
	routes, err = netlink.RouteList(link, netlink.FAMILY_V4)
	require.NoError(t, err)
	require.Len(t, routes, 1)
	assert.Equal(t, "10.99.0.2/32", routes[0].Dst.String())

	require.NoError(t, s.DownInterface())
	_, err = netlink.LinkByName("wgtest0")
	assert.Error(t, err)

	require.NoError(t, s.DownInterface(), "down on a missing device is a no-op")
}

func Test_State_SetUpInterface_badPeerKey(t *testing.T) {
	enterTestNetns(t)
	s, err := New(testConfig())
	require.NoError(t, err)
	defer func() { _ = s.DownInterface() }()

	bad := testPeer(t, "bad", "192.0.2.1", "10.99.0.1")
	bad.PubKey = "not a key"
	err = s.SetUpInterface([]overlay.Node{bad})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "converting received node information")
}
