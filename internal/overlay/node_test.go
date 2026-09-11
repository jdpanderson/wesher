package overlay

import (
	"encoding/json"
	"net/netip"
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
			OverlayAddr: ip,
			PubKey:      pubKey,
			AllowedIPs:  []netip.Prefix{netip.MustParsePrefix("192.168.7.0/24"), netip.MustParsePrefix("2001:db8:1::/48")},
			Identity:    [32]byte{1, 2, 3, 31: 32},
			Signature:   []byte("sig"),
		}
		encoded, err := node.EncodeMeta(1024)
		require.NoError(t, err)
		decoded := Node{Meta: encoded}
		require.NoError(t, decoded.DecodeMeta())

		node.Meta = encoded
		assert.Equal(t, node, decoded)
	}
}

// Only name, address and the encoded metadata are persisted; the decoded
// fields are derived from Meta on load.
func Test_Node_JSON(t *testing.T) {
	node := Node{Name: "n", Addr: netip.MustParseAddr("192.0.2.1"), Meta: []byte("m"), OverlayAddr: netip.MustParseAddr("10.0.0.1"), PubKey: "k", Identity: [32]byte{1}}
	b, err := json.Marshal(node)
	require.NoError(t, err)
	assert.JSONEq(t, `{"Name":"n","Addr":"192.0.2.1","Meta":"bQ=="}`, string(b))
}

func Test_Node_EncodeMeta_limit(t *testing.T) {
	node := Node{
		OverlayAddr: netip.MustParseAddr("10.0.0.1"),
		PubKey:      "abcdefghijklmnopkqstuvwxyzABCDEF",
	}
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
