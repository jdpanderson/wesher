package cli

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/jdpanderson/cheesecloth/internal/wg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_StatusCmd_Run(t *testing.T) {
	report, _, _ := statusFixture()
	status := func(iface string) (*wg.Report, error) {
		if iface != "wgoverlay" {
			return nil, errors.New("no such device")
		}
		return report, nil
	}

	// no cluster state for this interface on this host: peers are shown by key
	cmd := &StatusCmd{Interface: "wgoverlay", status: status}
	stdout, _, err := captureOutput(t, cmd.Run)
	require.NoError(t, err)
	assert.Contains(t, stdout, "interface: wgoverlay\n")
	assert.Contains(t, stdout, "peers:     2\n")
	assert.Contains(t, stdout, "KEYB")

	cmd.JSON = true
	stdout, _, err = captureOutput(t, cmd.Run)
	require.NoError(t, err)
	var got struct {
		Interface string `json:"interface"`
		Peers     []struct {
			PublicKey string `json:"publicKey"`
		} `json:"peers"`
	}
	require.NoError(t, json.Unmarshal([]byte(stdout), &got))
	assert.Equal(t, "wgoverlay", got.Interface)
	assert.Len(t, got.Peers, 2)

	_, _, err = captureOutput(t, (&StatusCmd{Interface: "absent0", status: status}).Run)
	assert.ErrorContains(t, err, "no such device")
}
