package cli

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/jdpanderson/cheesecloth/enroll"
	"github.com/jdpanderson/cheesecloth/trust"
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

// enrolServer starts an enrolment server on a loopback port and returns the port and a token.
func enrolServer(t *testing.T) (int, string) {
	t.Helper()
	id, err := trust.NewIdentity()
	require.NoError(t, err)
	set := trust.NewSet(id.Public())
	set.Merge(trust.Records{Admissions: []trust.Admission{trust.SelfAdmit(id, "root", time.Now())}})
	srv := &enroll.Server{Identity: id, Tokens: enroll.NewTokenStore(), Root: id.Public(), GossipAddr: "127.0.0.1:7946",
		Admit: func(joiner trust.PublicKey, dh trust.DHKey, name string) (trust.Admission, trust.Records, error) {
			a := trust.Admit(id, joiner, dh, name, 2, time.Now())
			set.Merge(trust.Records{Admissions: []trust.Admission{a}})
			return a, set.Records(), nil
		}}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go srv.Serve(ln)
	tok, err := srv.Tokens.Mint(time.Minute, 1)
	require.NoError(t, err)
	return ln.Addr().(*net.TCPAddr).Port, tok
}

func Test_AgentCmd_enrol(t *testing.T) {
	port, tok := enrolServer(t)
	joiner, err := trust.NewIdentity()
	require.NoError(t, err)
	cmd := validCmd()
	cmd.WireguardPort = port
	cmd.JoinKey = tok
	// the first host is down, the second carries a gossip port that must be replaced by the enrolment port
	cmd.Join = []string{"127.0.0.1:1", "127.0.0.1:7946"}
	unreachable := AgentCmd{WireguardPort: 1, JoinKey: tok, Join: []string{"127.0.0.1"}}

	_, _, err = unreachable.enrol(context.Background(), joiner, "j")
	assert.ErrorContains(t, err, "enrolling with 127.0.0.1:1")

	w, memberID, err := cmd.enrol(context.Background(), joiner, "j")
	require.NoError(t, err)
	assert.Equal(t, "127.0.0.1:7946", w.GossipAddr)
	assert.Equal(t, uint64(2), w.Admission.Host)
	assert.Equal(t, w.Root, memberID)
}
