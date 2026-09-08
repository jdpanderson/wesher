package cluster

import (
	"net/netip"
	"testing"

	"github.com/hashicorp/memberlist"
	"github.com/jdpanderson/wesher/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testDelegate() *delegateNode {
	n := &common.Node{Name: "node"}
	n.OverlayAddr = netip.MustParseAddr("10.0.0.1")
	n.PubKey = "abcdefghijklmnopkqstuvwxyzABCDEF"
	return &delegateNode{n}
}

func Test_delegateNode_NodeMeta(t *testing.T) {
	d := testDelegate()

	meta := d.NodeMeta(512)
	require.NotNil(t, meta)
	decoded := common.Node{Meta: meta}
	require.NoError(t, decoded.DecodeMeta())
	assert.Equal(t, d.OverlayAddr, decoded.OverlayAddr)
	assert.Equal(t, d.PubKey, decoded.PubKey)

	assert.Nil(t, d.NodeMeta(1), "over-limit metadata must yield nil")
}

func Test_delegateNode_noops(t *testing.T) {
	d := testDelegate()
	d.NotifyMsg(nil)
	d.MergeRemoteState(nil, true)
	d.NotifyConflict(nil, &memberlist.Node{Name: "other"})
	assert.Nil(t, d.GetBroadcasts(0, 0))
	assert.Nil(t, d.LocalState(true))
}
