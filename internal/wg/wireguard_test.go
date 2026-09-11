package wg

import (
	"net/netip"
	"testing"
	"time"

	"github.com/jdpanderson/cheesecloth/internal/overlay"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func Test_addrToIPNet(t *testing.T) {
	v4 := addrToIPNet(netip.MustParseAddr("10.0.0.1"))
	assert.Equal(t, "10.0.0.1/32", v4.String())

	v6 := addrToIPNet(netip.MustParseAddr("2001:db8::1"))
	assert.Equal(t, "2001:db8::1/128", v6.String())
}

func Test_State_nodesToPeerConfigs(t *testing.T) {
	key1 := wgtypes.Key{1}.String()
	key2 := wgtypes.Key{2}.String()

	n1 := overlay.Node{Name: "n1", Addr: netip.MustParseAddr("192.0.2.1")}
	n1.OverlayAddr = netip.MustParseAddr("10.0.0.1")
	n1.PubKey = key1
	n2 := overlay.Node{Name: "n2", Addr: netip.MustParseAddr("2001:db8::2")}
	n2.OverlayAddr = netip.MustParseAddr("fd00::2")
	n2.PubKey = key2

	s := &State{Port: 51820}
	cfgs, err := s.nodesToPeerConfigs([]overlay.Node{n1, n2})
	require.NoError(t, err)
	require.Len(t, cfgs, 2)

	assert.Equal(t, key1, cfgs[0].PublicKey.String())
	assert.True(t, cfgs[0].ReplaceAllowedIPs)
	assert.Nil(t, cfgs[0].PersistentKeepaliveInterval, "keepalive off by default")
	assert.Equal(t, "192.0.2.1:51820", cfgs[0].Endpoint.String())
	assert.Equal(t, "10.0.0.1/32", cfgs[0].AllowedIPs[0].String())

	assert.Equal(t, key2, cfgs[1].PublicKey.String())
	assert.Equal(t, "[2001:db8::2]:51820", cfgs[1].Endpoint.String())
	assert.Equal(t, "fd00::2/128", cfgs[1].AllowedIPs[0].String())
}

func Test_State_nodesToPeerConfigs_keepalive(t *testing.T) {
	n := overlay.Node{Name: "n", Addr: netip.MustParseAddr("192.0.2.1")}
	n.OverlayAddr = netip.MustParseAddr("10.0.0.1")
	n.PubKey = wgtypes.Key{1}.String()

	s := &State{Port: 51820, keepalive: 25 * time.Second}
	cfgs, err := s.nodesToPeerConfigs([]overlay.Node{n})
	require.NoError(t, err)
	require.NotNil(t, cfgs[0].PersistentKeepaliveInterval)
	assert.Equal(t, 25*time.Second, *cfgs[0].PersistentKeepaliveInterval)
}

func Test_State_nodesToPeerConfigs_badKey(t *testing.T) {
	n := overlay.Node{Name: "n", Addr: netip.MustParseAddr("192.0.2.1")}
	n.OverlayAddr = netip.MustParseAddr("10.0.0.1")
	n.PubKey = "not a key"

	_, err := (&State{}).nodesToPeerConfigs([]overlay.Node{n})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parsing wireguard key")
}

func Test_State_nodesToPeerConfigs_empty(t *testing.T) {
	cfgs, err := (&State{}).nodesToPeerConfigs(nil)
	require.NoError(t, err)
	assert.Empty(t, cfgs)
}
