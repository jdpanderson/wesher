package wg

import (
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func Test_status_fake(t *testing.T) {
	handshake := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	_, allowed, _ := net.ParseCIDR("10.99.0.2/32")
	_, allowed6, _ := net.ParseCIDR("fd00::2/128")
	_, routed, _ := net.ParseCIDR("192.168.7.0/24")
	dev := &wgtypes.Device{
		Name: "wgtest0", ListenPort: 51820, PublicKey: wgtypes.Key{9},
		Peers: []wgtypes.Peer{
			{
				PublicKey: wgtypes.Key{1}, Endpoint: &net.UDPAddr{IP: net.ParseIP("192.0.2.2"), Port: 51820},
				AllowedIPs: []net.IPNet{*allowed}, LastHandshakeTime: handshake,
				ReceiveBytes: 100, TransmitBytes: 200, PersistentKeepaliveInterval: 25 * time.Second,
			},
			{PublicKey: wgtypes.Key{2}, AllowedIPs: []net.IPNet{*allowed, *allowed6}}, // never connected, two allowed IPs
			{PublicKey: wgtypes.Key{3}, AllowedIPs: []net.IPNet{*allowed, *routed}},   // also routes a network
		},
	}
	link := &fakeLinker{addrs: []netip.Prefix{netip.MustParsePrefix("fe80::1/64"), netip.MustParsePrefix("10.99.0.1/32")}}

	r, err := status("wgtest0", "utun3", &fakeWG{device: dev}, link)
	require.NoError(t, err)
	assert.Equal(t, "utun3", link.iface, "addresses come from the operating system's interface")
	assert.Equal(t, "wgtest0", r.Interface)
	assert.Equal(t, 51820, r.ListenPort)
	assert.Equal(t, wgtypes.Key{9}.String(), r.PublicKey)
	assert.Equal(t, []netip.Prefix{netip.MustParsePrefix("10.99.0.1/32")}, r.Addrs, "link-local is filtered out")
	require.Len(t, r.Peers, 3)

	p := r.Peers[0]
	assert.Equal(t, "192.0.2.2:51820", p.Endpoint)
	assert.Equal(t, handshake, p.LastHandshake)
	assert.EqualValues(t, 100, p.ReceiveBytes)
	assert.EqualValues(t, 200, p.TransmitBytes)
	assert.Equal(t, 25*time.Second, p.PersistentKeepalive)
	assert.Equal(t, []netip.Prefix{netip.MustParsePrefix("10.99.0.2/32")}, p.AllowedIPs)

	p = r.Peers[1]
	assert.Empty(t, p.Endpoint)
	assert.True(t, p.LastHandshake.IsZero())
	assert.Equal(t, []netip.Prefix{netip.MustParsePrefix("10.99.0.2/32"), netip.MustParsePrefix("fd00::2/128")}, p.AllowedIPs)

	p = r.Peers[2]
	assert.Equal(t, []netip.Prefix{netip.MustParsePrefix("10.99.0.2/32"), netip.MustParsePrefix("192.168.7.0/24")}, p.AllowedIPs)
}

func Test_status_fake_errors(t *testing.T) {
	boom := errors.New("boom")
	_, err := status("wgtest0", "wgtest0", &fakeWG{deviceErr: boom}, &fakeLinker{})
	assert.ErrorContains(t, err, "getting wireguard device")

	_, err = status("wgtest0", "wgtest0", &fakeWG{}, &fakeLinker{errs: map[string]error{"Addrs": boom}})
	assert.ErrorContains(t, err, "listing addresses")
}

func Test_prefixFromIPNet(t *testing.T) {
	_, v4, _ := net.ParseCIDR("10.0.0.1/32")
	p, ok := prefixFromIPNet(v4)
	require.True(t, ok)
	assert.Equal(t, "10.0.0.1/32", p.String())

	mapped := &net.IPNet{IP: net.ParseIP("10.0.0.0"), Mask: net.CIDRMask(104, 128)} // 16-byte v4 with a v6 mask
	p, ok = prefixFromIPNet(mapped)
	require.True(t, ok)
	assert.Equal(t, "10.0.0.0/8", p.String())

	_, ok = prefixFromIPNet(nil)
	assert.False(t, ok)
	_, ok = prefixFromIPNet(&net.IPNet{IP: net.IP{1, 2, 3}, Mask: net.CIDRMask(8, 32)})
	assert.False(t, ok, "malformed address")
}
