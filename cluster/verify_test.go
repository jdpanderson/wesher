package cluster

import (
	"net/netip"
	"testing"
	"time"

	"github.com/jdpanderson/cheesecloth/common"
	"github.com/jdpanderson/cheesecloth/trust"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_assignedAddr_and_verifyMeta(t *testing.T) {
	root, a, b, stranger := testIdentity(t), testIdentity(t), testIdentity(t), testIdentity(t)
	t0 := time.Unix(1_700_000_000, 0)
	set := trust.NewSet(root.Public())
	set.Merge(trust.Records{Admissions: []trust.Admission{
		trust.SelfAdmit(root, "root", t0),
		trust.Admit(root, a.Public(), a.DHPublic(), "a", 2, t0),
		trust.Admit(root, b.Public(), b.DHPublic(), "b", 2, t0.Add(time.Second)), // same slot, later
	}})

	addr, err := assignedAddr(set, testOverlay, root.Public())
	require.NoError(t, err)
	assert.Equal(t, "10.0.0.1", addr.String())
	addr, err = assignedAddr(set, testOverlay, a.Public())
	require.NoError(t, err)
	assert.Equal(t, "10.0.0.2", addr.String())
	_, err = assignedAddr(set, testOverlay, b.Public())
	assert.ErrorContains(t, err, "collides with a")
	_, err = assignedAddr(set, testOverlay, stranger.Public())
	assert.ErrorContains(t, err, "not a member")
	_, err = assignedAddr(set, netip.MustParsePrefix("10.0.0.0/31"), a.Public())
	assert.ErrorContains(t, err, "does not fit")

	// metadata must claim the assigned address, signed by the identity
	meta := func(id *trust.Identity, name, overlay string) *common.Node {
		n := &common.Node{Name: name}
		n.OverlayAddr = netip.MustParseAddr(overlay)
		n.PubKey = testKey
		n.Identity = id.Public()
		n.Signature = id.Sign(trust.MetaDigest(n.Name, n.OverlayAddr, n.PubKey, nil))
		var encErr error
		n.Meta, encErr = n.EncodeMeta(512)
		require.NoError(t, encErr)
		return &common.Node{Name: n.Name, Meta: n.Meta}
	}
	id, err := verifyMeta(set, testOverlay, meta(a, "a", "10.0.0.2"))
	require.NoError(t, err)
	assert.Equal(t, a.Public(), id)
	_, err = verifyMeta(set, testOverlay, meta(a, "a", "10.0.0.9"))
	assert.ErrorContains(t, err, "is assigned 10.0.0.2")
	_, err = verifyMeta(set, testOverlay, meta(b, "b", "10.0.0.2"))
	assert.ErrorContains(t, err, "collides")

	bad := meta(a, "a", "10.0.0.2")
	var n common.Node
	n.OverlayAddr = netip.MustParseAddr("10.0.0.2")
	n.PubKey = "not a wireguard key"
	n.Identity = a.Public()
	n.Signature = a.Sign(trust.MetaDigest("a", n.OverlayAddr, n.PubKey, nil))
	bad.Meta, err = n.EncodeMeta(512)
	require.NoError(t, err)
	_, err = verifyMeta(set, testOverlay, bad)
	assert.ErrorContains(t, err, "wireguard key")
}

// testKey is a syntactically valid wireguard public key.
const testKey = "gm/3EV7bl46Z2QPUa5CppLUjwoL45BwHO1nrEgIFsFA="
