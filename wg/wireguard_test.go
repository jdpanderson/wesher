package wg

import (
	"net"
	"net/netip"
	"testing"

	"github.com/costela/wesher/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func Test_State_AssignOverlayAddr(t *testing.T) {
	type args struct {
		prefix   netip.Prefix
		hostname string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			"assign in big ipv4 net",
			args{netip.MustParsePrefix("10.0.0.0/8"), "test"},
			"10.221.153.165", // if we ever have to change this, we should probably also mark it as a breaking change
		},
		{
			"assign in small ipv4 net",
			args{netip.MustParsePrefix("10.0.0.0/24"), "test"},
			"10.0.0.165", // if we ever have to change this, we should probably also mark it as a breaking change
		},
		{
			"assign in ipv6 net",
			args{netip.MustParsePrefix("2001:db8::/32"), "test"},
			"2001:db8:c575:7277:b806:e994:13dd:99a5", // if we ever have to change this, we should probably also mark it as a breaking change
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &State{}
			err := s.assignOverlayAddr(tt.args.prefix, tt.args.hostname)
			require.NoError(t, err)

			assert.Equal(t, tt.want, s.OverlayAddr.String())
		})
	}
}

// This is just to ensure - if we ever change the hashing function - that it spreads the results in a way that at least
// avoids the most obvious collisions.
func Test_State_AssignOverlayAddr_no_obvious_collisions(t *testing.T) {
	prefix := netip.MustParsePrefix("10.0.0.0/24")
	assignments := make(map[string]string)
	for _, n := range []string{"test", "test1", "test2", "1test", "2test"} {
		s := &State{}
		err := s.assignOverlayAddr(prefix, n)
		require.NoError(t, err)

		assert.NotContainsf(t, assignments, s.OverlayAddr.String(), "IP assignment collision for hostname %q", n)

		assignments[s.OverlayAddr.String()] = n
	}
}

// This should ensure the obvious fact that the same name should map to the same IP if called twice.
func Test_State_AssignOverlayAddr_consistent(t *testing.T) {
	prefix := netip.MustParsePrefix("10.0.0.0/8")
	s1 := &State{}
	err := s1.assignOverlayAddr(prefix, "test")
	require.NoError(t, err)

	s2 := &State{}
	err = s2.assignOverlayAddr(prefix, "test")
	require.NoError(t, err)

	assert.Equal(t, s1.OverlayAddr.String(), s2.OverlayAddr.String())
}

func Test_State_AssignOverlayAddr_repeatable(t *testing.T) {
	prefix := netip.MustParsePrefix("10.0.0.0/8")
	s := &State{}
	err := s.assignOverlayAddr(prefix, "test")
	require.NoError(t, err)
	gen1 := s.OverlayAddr.String()

	err = s.assignOverlayAddr(prefix, "test")
	require.NoError(t, err)
	gen2 := s.OverlayAddr.String()

	assert.Equal(t, gen1, gen2)
}

func Test_State_AssignOverlayAddr_edgeMasks(t *testing.T) {
	tests := []struct {
		name   string
		prefix string
		want   string
	}{
		// /32 leaves nothing to assign: node gets the network address itself
		{"host prefix", "10.1.2.3/32", "10.1.2.3"},
		// non-byte-aligned masks round down: /20 only replaces the last byte
		{"mask not multiple of 8", "10.0.0.0/20", "10.0.0.165"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &State{}
			require.NoError(t, s.assignOverlayAddr(netip.MustParsePrefix(tt.prefix), "test"))
			assert.Equal(t, tt.want, s.OverlayAddr.String())
		})
	}
}

func Test_addrToIPNet(t *testing.T) {
	v4 := addrToIPNet(netip.MustParseAddr("10.0.0.1"))
	assert.Equal(t, "10.0.0.1/32", v4.String())

	v6 := addrToIPNet(netip.MustParseAddr("2001:db8::1"))
	assert.Equal(t, "2001:db8::1/128", v6.String())
}

func Test_State_nodesToPeerConfigs(t *testing.T) {
	key1 := wgtypes.Key{1}.String()
	key2 := wgtypes.Key{2}.String()

	n1 := common.Node{Name: "n1", Addr: net.ParseIP("192.0.2.1")}
	n1.OverlayAddr = netip.MustParseAddr("10.0.0.1")
	n1.PubKey = key1
	n2 := common.Node{Name: "n2", Addr: net.ParseIP("2001:db8::2")}
	n2.OverlayAddr = netip.MustParseAddr("fd00::2")
	n2.PubKey = key2

	s := &State{Port: 51820}
	cfgs, err := s.nodesToPeerConfigs([]common.Node{n1, n2})
	require.NoError(t, err)
	require.Len(t, cfgs, 2)

	assert.Equal(t, key1, cfgs[0].PublicKey.String())
	assert.True(t, cfgs[0].ReplaceAllowedIPs)
	assert.Equal(t, "192.0.2.1:51820", cfgs[0].Endpoint.String())
	assert.Equal(t, "10.0.0.1/32", cfgs[0].AllowedIPs[0].String())

	assert.Equal(t, key2, cfgs[1].PublicKey.String())
	assert.Equal(t, "[2001:db8::2]:51820", cfgs[1].Endpoint.String())
	assert.Equal(t, "fd00::2/128", cfgs[1].AllowedIPs[0].String())
}

func Test_State_nodesToPeerConfigs_badKey(t *testing.T) {
	n := common.Node{Name: "n", Addr: net.ParseIP("192.0.2.1")}
	n.OverlayAddr = netip.MustParseAddr("10.0.0.1")
	n.PubKey = "not a key"

	_, err := (&State{}).nodesToPeerConfigs([]common.Node{n})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parsing wireguard key")
}

func Test_State_nodesToPeerConfigs_empty(t *testing.T) {
	cfgs, err := (&State{}).nodesToPeerConfigs(nil)
	require.NoError(t, err)
	assert.Empty(t, cfgs)
}
