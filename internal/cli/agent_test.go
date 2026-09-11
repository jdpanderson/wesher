package cli

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/jdpanderson/cheesecloth/internal/cluster"
	"github.com/jdpanderson/cheesecloth/internal/trust"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testOverlay = netip.MustParsePrefix("10.0.0.0/8")

// validCmd returns an AgentCmd with the flag defaults that Validate requires.
func validCmd() AgentCmd {
	return AgentCmd{OverlayNet: testOverlay, MTU: 1420, BindAddr: netip.IPv4Unspecified()}
}

func Test_AgentCmd_Validate_errors(t *testing.T) {
	tests := []struct {
		name    string
		cmd     AgentCmd
		wantErr string
	}{
		{
			"overlay too small",
			AgentCmd{OverlayNet: netip.MustParsePrefix("10.0.0.0/31"), MTU: 1420},
			"no room for two nodes",
		},
		{
			"allowed ips inside the overlay",
			AgentCmd{OverlayNet: testOverlay, MTU: 1420, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.5.0.0/16")}},
			"overlaps the overlay network",
		},
		{
			"mtu too small",
			AgentCmd{OverlayNet: testOverlay, MTU: 500},
			"unsupported MTU",
		},
		{
			"keepalive not whole seconds",
			AgentCmd{OverlayNet: testOverlay, MTU: 1420, PersistentKeepalive: 1500 * time.Millisecond},
			"unsupported persistent keepalive",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cmd.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func Test_AgentCmd_Validate_masksAllowedIPs(t *testing.T) {
	cmd := validCmd()
	cmd.AllowedIPs = []netip.Prefix{netip.MustParsePrefix("192.168.7.9/24")}
	require.NoError(t, cmd.Validate())
	assert.Equal(t, "192.168.7.0/24", cmd.AllowedIPs[0].String())
}

func Test_AgentCmd_Validate_joinKey(t *testing.T) {
	cmd := validCmd()
	cmd.JoinKey = "token"
	assert.ErrorContains(t, cmd.Validate(), "needs --join")
	cmd.Join = []string{"member"}
	require.NoError(t, cmd.Validate())
	cmd.Init = true
	assert.ErrorContains(t, cmd.Validate(), "cannot be combined")
}

func Test_AgentCmd_enrolAddrs(t *testing.T) {
	cmd := AgentCmd{ClusterPort: 7946, Join: []string{"member", "10.0.0.1:1234", "fd00::1", "[fd00::2]:99"}}
	assert.Equal(t, []string{"member:7946", "10.0.0.1:1234", "[fd00::1]:7946", "[fd00::2]:99"}, cmd.enrolAddrs())
}

func Test_AgentCmd_bootstrap(t *testing.T) {
	newBoot := func() *cluster.Bootstrap {
		id, err := trust.NewIdentity()
		require.NoError(t, err)
		return &cluster.Bootstrap{Identity: id}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	// not a member and nothing asked for: told what to do
	_, err := (&AgentCmd{}).bootstrap(ctx, newBoot(), "h")
	assert.ErrorContains(t, err, "not a member of any cluster")

	// --init: root of a new cluster, joining whatever --join names
	boot := newBoot()
	addrs, err := (&AgentCmd{Init: true, Join: []string{"x"}}).bootstrap(ctx, boot, "h")
	require.NoError(t, err)
	assert.Equal(t, []string{"x"}, addrs)
	assert.True(t, boot.Enrolled())
	assert.Equal(t, boot.Identity.Public(), boot.Root)
	require.Len(t, boot.Records.Admissions, 1)
	assert.Equal(t, "h", boot.Records.Admissions[0].Name)

	// already enrolled: the join key is ignored, --join is used as given
	addrs, err = (&AgentCmd{JoinKey: "stale", Join: []string{"a", "b"}}).bootstrap(ctx, boot, "h")
	require.NoError(t, err)
	assert.Equal(t, []string{"a", "b"}, addrs)

	// --join-key with no reachable member fails
	_, err = (&AgentCmd{ClusterPort: 1, JoinKey: "token", Join: []string{"127.0.0.1"}}).bootstrap(ctx, newBoot(), "h")
	assert.ErrorContains(t, err, "enrolling with 127.0.0.1:1")
}

func Test_AgentCmd_enrol_unreachable(t *testing.T) {
	joiner, err := trust.NewIdentity()
	require.NoError(t, err)
	cmd := AgentCmd{ClusterPort: 1, JoinKey: "token", Join: []string{"127.0.0.1", "127.0.0.1:2"}}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_, err = cmd.enrol(ctx, joiner, "j")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "enrolling with 127.0.0.1:2", "the last member tried is reported")
}
