package cli

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/jdpanderson/cheesecloth/overlay"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type fakeCluster struct {
	ch   chan []overlay.Node
	left bool
}

func (f *fakeCluster) Members() <-chan []overlay.Node { return f.ch }
func (f *fakeCluster) Leave()                         { f.left = true }

type fakeWG struct {
	upErr error
	ups   [][]overlay.Node
	downs int
}

func (f *fakeWG) SetUpInterface(nodes []overlay.Node) error {
	f.ups = append(f.ups, nodes)
	return f.upErr
}
func (f *fakeWG) DownInterface() error { f.downs++; return nil }

type fakeHosts struct{ writes []map[string][]string }

func (f *fakeHosts) WriteEntries(m map[string][]string) error {
	f.writes = append(f.writes, m)
	return nil
}

// verifiedNode is a node as the cluster hands it over: metadata decoded and checked.
func verifiedNode(t *testing.T, name, addr, overlayAddr string, routes ...string) overlay.Node {
	t.Helper()
	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	n := overlay.Node{Name: name, Addr: net.ParseIP(addr)}
	n.OverlayAddr = netip.MustParseAddr(overlayAddr)
	n.PubKey = key.PublicKey().String()
	for _, r := range routes {
		n.AllowedIPs = append(n.AllowedIPs, netip.MustParsePrefix(r))
	}
	return n
}

func runLoop(t *testing.T, a *AgentCmd, cl *fakeCluster, wg *fakeWG, hosts *fakeHosts) (context.CancelFunc, <-chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- a.loop(ctx, cl.ch, cl, wg, hosts) }()
	return cancel, errc
}

func waitErr(t *testing.T, errc <-chan error) error {
	t.Helper()
	select {
	case err := <-errc:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("loop did not return")
		return nil
	}
}

func Test_AgentCmd_loop_appliesAndTearsDown(t *testing.T) {
	cl := &fakeCluster{ch: make(chan []overlay.Node)}
	wg := &fakeWG{}
	hosts := &fakeHosts{}
	cancel, errc := runLoop(t, &AgentCmd{OverlayNet: testOverlay}, cl, wg, hosts)

	cl.ch <- []overlay.Node{verifiedNode(t, "good", "192.0.2.1", "10.0.0.1")}

	cancel()
	require.NoError(t, waitErr(t, errc))

	require.Len(t, wg.ups, 1)
	require.Len(t, wg.ups[0], 1)
	assert.Equal(t, "good", wg.ups[0][0].Name)
	require.Len(t, hosts.writes, 2)
	assert.Equal(t, map[string][]string{"10.0.0.1": {"good"}}, hosts.writes[0])
	assert.Empty(t, hosts.writes[1], "hosts entries cleared on shutdown")
	assert.True(t, cl.left)
	assert.Equal(t, 1, wg.downs)
}

func Test_AgentCmd_apply_allowedIPs(t *testing.T) {
	wg := &fakeWG{}
	a := &AgentCmd{OverlayNet: testOverlay, NoEtcHosts: true}
	// z is listed first but b wins the shared network by name; the overlay-net prefix is dropped
	z := verifiedNode(t, "z", "192.0.2.1", "10.0.0.1", "192.168.7.0/24", "10.9.0.0/16", "172.16.0.0/12")
	b := verifiedNode(t, "b", "192.0.2.2", "10.0.0.2", "192.168.7.0/24")
	a.apply([]overlay.Node{z, b}, wg, &fakeHosts{})

	require.Len(t, wg.ups, 1)
	require.Len(t, wg.ups[0], 2)
	assert.Equal(t, "b", wg.ups[0][0].Name)
	assert.Equal(t, []netip.Prefix{netip.MustParsePrefix("192.168.7.0/24")}, wg.ups[0][0].AllowedIPs)
	assert.Equal(t, "z", wg.ups[0][1].Name)
	assert.Equal(t, []netip.Prefix{netip.MustParsePrefix("172.16.0.0/12")}, wg.ups[0][1].AllowedIPs)
}

func Test_AgentCmd_loop_notifiesSystemd(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notify.sock")
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	t.Setenv("NOTIFY_SOCKET", path)
	read := func() string {
		buf := make([]byte, 1024)
		require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
		n, rerr := conn.Read(buf)
		require.NoError(t, rerr)
		return string(buf[:n])
	}

	cl := &fakeCluster{ch: make(chan []overlay.Node)}
	cancel, errc := runLoop(t, &AgentCmd{OverlayNet: testOverlay, NoEtcHosts: true}, cl, &fakeWG{}, &fakeHosts{})

	cl.ch <- nil // a lone node: ready with no peers
	assert.Equal(t, "READY=1\nSTATUS=0 peers", read())
	cl.ch <- []overlay.Node{verifiedNode(t, "n", "192.0.2.1", "10.0.0.1")}
	assert.Equal(t, "STATUS=1 peers", read())
	cancel()
	assert.Equal(t, "STOPPING=1", read())
	require.NoError(t, waitErr(t, errc))
}

func Test_AgentCmd_loop_noEtcHosts(t *testing.T) {
	cl := &fakeCluster{ch: make(chan []overlay.Node)}
	wg := &fakeWG{}
	hosts := &fakeHosts{}
	cancel, errc := runLoop(t, &AgentCmd{OverlayNet: testOverlay, NoEtcHosts: true}, cl, wg, hosts)

	cl.ch <- []overlay.Node{verifiedNode(t, "n", "192.0.2.1", "10.0.0.1")}
	cancel()
	require.NoError(t, waitErr(t, errc))
	assert.Empty(t, hosts.writes)
}

func Test_AgentCmd_loop_setupFailureDownsInterface(t *testing.T) {
	cl := &fakeCluster{ch: make(chan []overlay.Node)}
	wg := &fakeWG{upErr: errors.New("boom")}
	cancel, errc := runLoop(t, &AgentCmd{OverlayNet: testOverlay, NoEtcHosts: true}, cl, wg, &fakeHosts{})

	cl.ch <- []overlay.Node{verifiedNode(t, "n", "192.0.2.1", "10.0.0.1")}
	cancel()
	require.NoError(t, waitErr(t, errc))
	assert.Equal(t, 2, wg.downs, "once after the failed setup, once on shutdown")
}

func Test_AgentCmd_loop_closedChannel(t *testing.T) {
	cl := &fakeCluster{ch: make(chan []overlay.Node)}
	_, errc := runLoop(t, &AgentCmd{}, cl, &fakeWG{}, &fakeHosts{})
	close(cl.ch)
	err := waitErr(t, errc)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "channel closed")
}
