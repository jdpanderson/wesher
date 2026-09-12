package enrol

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_frames(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, writeFrame(&buf, proof{MAC: []byte{1, 2, 3}}))
	require.NoError(t, writeFrame(&buf, hello{Name: "n"}))
	var p proof
	require.NoError(t, readFrame(&buf, &p))
	assert.Equal(t, []byte{1, 2, 3}, p.MAC)
	var h hello
	require.NoError(t, readFrame(&buf, &h))
	assert.Equal(t, "n", h.Name)
	assert.Zero(t, buf.Len())

	assert.Error(t, writeFrame(&buf, func() {}), "not JSON")
	assert.ErrorContains(t, writeFrame(&buf, strings.Repeat("x", maxFrame)), "frame too large")

	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], maxFrame+1)
	assert.ErrorContains(t, readFrame(bytes.NewReader(hdr[:]), &h), "frame too large")
	binary.BigEndian.PutUint32(hdr[:], 10)
	assert.Error(t, readFrame(bytes.NewReader(append(hdr[:], 1, 2)), &h), "truncated body")
	assert.Error(t, readFrame(bytes.NewReader(hdr[:2]), &h), "truncated header")
}

// A member too old to send the overlay network leaves the field out, which
// reads as "not known" rather than as a network.
func Test_Welcome_overlayNetOptional(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, writeFrame(&buf, Welcome{GossipAddr: "192.0.2.1:7946"}))
	assert.NotContains(t, buf.String(), "overlayNet", "a zero prefix is not sent")

	var w Welcome
	require.NoError(t, readFrame(&buf, &w))
	assert.False(t, w.OverlayNet.IsValid())

	buf.Reset()
	require.NoError(t, writeFrame(&buf, Welcome{OverlayNet: netip.MustParsePrefix("fd00:10::/64")}))
	require.NoError(t, readFrame(&buf, &w))
	assert.Equal(t, netip.MustParsePrefix("fd00:10::/64"), w.OverlayNet)
}

func Test_randomNonce(t *testing.T) {
	a, err := randomNonce()
	require.NoError(t, err)
	b, err := randomNonce()
	require.NoError(t, err)
	assert.Len(t, a, nonceLen)
	assert.NotEqual(t, a, b)
}

func Test_mac_labels(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	tr := []byte("transcript")
	assert.NotEqual(t, mac(key, labelMember, tr), mac(key, labelJoiner, tr), "each side proves with its own label")
	assert.Equal(t, mac(key, labelMember, tr), mac(key, labelMember, tr))
	// the label is terminated, so it cannot bleed into the transcript
	assert.NotEqual(t, mac(key, "ab", []byte("c")), mac(key, "a", []byte("bc")))
}
