package common

import (
	"net/netip"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Node_Encode_Decode(t *testing.T) {
	pubKey := "abcdefghijklmnopkqstuvwxyzABCDEF"
	ipv4 := netip.MustParseAddr("10.0.0.1")
	ipv6 := netip.MustParseAddr("2001:db8::1")

	for _, ip := range []netip.Addr{ipv4, ipv6} {
		node := Node{
			nodeMeta: nodeMeta{
				OverlayAddr: ip,
				PubKey:      pubKey,
				AllowedIPs:  []netip.Prefix{netip.MustParsePrefix("192.168.7.0/24"), netip.MustParsePrefix("2001:db8:1::/48")},
				Identity:    [32]byte{1, 2, 3, 31: 32},
				Signature:   []byte("sig"),
			},
		}
		encoded, _ := node.EncodeMeta(1024)
		new := Node{Meta: encoded}

		err := new.DecodeMeta()
		require.NoError(t, err)

		if !reflect.DeepEqual(node.nodeMeta, new.nodeMeta) {
			t.Errorf("node encoding then decoding mismatch: %s / %s", node.nodeMeta, new.nodeMeta)
		}
	}
}

func Test_Node_EncodeMeta_limit(t *testing.T) {
	node := Node{nodeMeta: nodeMeta{
		OverlayAddr: netip.MustParseAddr("10.0.0.1"),
		PubKey:      "abcdefghijklmnopkqstuvwxyzABCDEF",
	}}
	_, err := node.EncodeMeta(1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "could not fit node metadata")
}

func Test_Node_DecodeMeta_garbage(t *testing.T) {
	for _, meta := range [][]byte{nil, {}, []byte("not json"), []byte(`{"id":"YWJj"}`)} {
		n := Node{Meta: meta}
		err := n.DecodeMeta()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "decoding node meta")
	}
}
