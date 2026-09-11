package cli

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"regexp"
	"testing"
	"time"

	"github.com/jdpanderson/cheesecloth/trust"
	"github.com/jdpanderson/cheesecloth/wg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// identityB is peer b's identity in the fixture.
var identityB = trust.PublicKey{7, 7, 7}

func statusFixture() (*wg.Report, map[string]peerInfo, time.Time) {
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	r := &wg.Report{
		Interface: "wgoverlay", PublicKey: "LOCALKEY", ListenPort: 51820,
		Addrs: []netip.Prefix{netip.MustParsePrefix("10.0.0.1/32")},
		Peers: []wg.PeerReport{
			{PublicKey: "KEYB", Endpoint: "192.0.2.2:51820", AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.2/32"), netip.MustParsePrefix("192.168.7.0/24")},
				LastHandshake: now.Add(-42 * time.Second), ReceiveBytes: 1536, TransmitBytes: 3 * 1024 * 1024},
			{PublicKey: "KEYUNKNOWN1234567890", AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.3/32")}},
		},
	}
	return r, map[string]peerInfo{"KEYB": {Name: "b", Identity: &identityB}}, now
}

func Test_renderStatus(t *testing.T) {
	r, names, now := statusFixture()
	var buf bytes.Buffer
	require.NoError(t, renderStatus(&buf, r, trust.PublicKey{}, names, now))
	out := buf.String()
	assert.Contains(t, out, "identity:  -\n")

	assert.Contains(t, out, "interface: wgoverlay\n")
	assert.Contains(t, out, "address:   10.0.0.1/32\n")
	assert.Contains(t, out, "peers:     2\n")
	assert.Regexp(t, `KEYUNKNOWN12\.\.\.\s+-\s+10\.0\.0\.3\s+-\s+never\s+0 B\s+0 B\s+-`, out, "unknown peer: short key, no identity, no endpoint, never, no routes")
	assert.Regexp(t, `\nb\s+`+regexp.QuoteMeta(identityB.Short())+`\s+10\.0\.0\.2\s+192\.0\.2\.2:51820\s+42s ago\s+1\.5 KiB\s+3\.0 MiB\s+192\.168\.7\.0/24`, out)
	assert.Less(t, bytes.Index(buf.Bytes(), []byte("\nKEYUNKNOWN")), bytes.Index(buf.Bytes(), []byte("\nb ")), "sorted by name")
}

func Test_renderStatus_noPeers(t *testing.T) {
	r, names, now := statusFixture()
	r.Peers = nil
	var buf bytes.Buffer
	require.NoError(t, renderStatus(&buf, r, trust.PublicKey{}, names, now))
	assert.Contains(t, buf.String(), "peers:     0\n")
	assert.NotContains(t, buf.String(), "NAME")
}

func Test_renderStatusJSON(t *testing.T) {
	r, names, _ := statusFixture()
	var buf bytes.Buffer
	var local trust.PublicKey
	local[0] = 7
	require.NoError(t, renderStatusJSON(&buf, r, local, names))

	var got struct {
		Interface string `json:"interface"`
		Identity  string `json:"identity"`
		Peers     []struct {
			Name      string `json:"name"`
			Identity  string `json:"identity"`
			PublicKey string `json:"publicKey"`
			Endpoint  string `json:"endpoint"`
		} `json:"peers"`
	}
	require.NoError(t, json.Unmarshal(buf.Bytes(), &got))
	assert.Equal(t, "wgoverlay", got.Interface)
	assert.Equal(t, local.String(), got.Identity)
	require.Len(t, got.Peers, 2)
	assert.Equal(t, "b", got.Peers[0].Name)
	assert.Equal(t, identityB.String(), got.Peers[0].Identity)
	assert.Equal(t, "192.0.2.2:51820", got.Peers[0].Endpoint)
	assert.Empty(t, got.Peers[1].Name)
}

func Test_humanBytes(t *testing.T) {
	assert.Equal(t, "0 B", humanBytes(0))
	assert.Equal(t, "1023 B", humanBytes(1023))
	assert.Equal(t, "1.0 KiB", humanBytes(1024))
	assert.Equal(t, "1.5 GiB", humanBytes(1536*1024*1024))
}
