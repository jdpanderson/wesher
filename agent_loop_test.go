package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/costela/wesher/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type fakeCluster struct {
	ch   chan []common.Node
	left bool
}

func (f *fakeCluster) Members() <-chan []common.Node { return f.ch }
func (f *fakeCluster) Leave()                        { f.left = true }

type fakeWG struct {
	upErr error
	ups   [][]common.Node
	downs int
}

func (f *fakeWG) SetUpInterface(nodes []common.Node) error {
	f.ups = append(f.ups, nodes)
	return f.upErr
}
func (f *fakeWG) DownInterface() error { f.downs++; return nil }

type fakeHosts struct{ writes []map[string][]string }

func (f *fakeHosts) WriteEntries(m map[string][]string) error {
	f.writes = append(f.writes, m)
	return nil
}

func encodedNode(t *testing.T, name, addr, overlay string) common.Node {
	t.Helper()
	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	return encodedNodeWithKey(t, name, addr, overlay, key.PublicKey().String())
}

func encodedNodeWithKey(t *testing.T, name, addr, overlay, pubKey string) common.Node {
	t.Helper()
	src := common.Node{}
	src.OverlayAddr = netip.MustParseAddr(overlay)
	src.PubKey = pubKey
	meta, err := src.EncodeMeta(512)
	require.NoError(t, err)
	return common.Node{Name: name, Addr: net.ParseIP(addr), Meta: meta}
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
	cl := &fakeCluster{ch: make(chan []common.Node)}
	wg := &fakeWG{}
	hosts := &fakeHosts{}
	cancel, errc := runLoop(t, &AgentCmd{OverlayNet: testOverlay}, cl, wg, hosts)

	good := encodedNode(t, "good", "192.0.2.1", "10.0.0.1")
	bad := common.Node{Name: "bad", Addr: net.ParseIP("192.0.2.2"), Meta: []byte("garbage")}
	outside := encodedNode(t, "outside", "192.0.2.3", "192.168.7.7")
	badKey := encodedNodeWithKey(t, "badkey", "192.0.2.4", "10.0.0.4", "not-a-key")
	cl.ch <- []common.Node{good, bad, outside, badKey}

	cancel()
	require.NoError(t, waitErr(t, errc))

	require.Len(t, wg.ups, 1)
	require.Len(t, wg.ups[0], 1, "undecodable, out-of-net and bad-key nodes must be skipped")
	assert.Equal(t, "good", wg.ups[0][0].Name)
	require.Len(t, hosts.writes, 2)
	assert.Equal(t, map[string][]string{"10.0.0.1": {"good"}}, hosts.writes[0])
	assert.Empty(t, hosts.writes[1], "hosts entries cleared on shutdown")
	assert.True(t, cl.left)
	assert.Equal(t, 1, wg.downs)
}

func Test_AgentCmd_loop_noEtcHosts(t *testing.T) {
	cl := &fakeCluster{ch: make(chan []common.Node)}
	wg := &fakeWG{}
	hosts := &fakeHosts{}
	cancel, errc := runLoop(t, &AgentCmd{OverlayNet: testOverlay, NoEtcHosts: true}, cl, wg, hosts)

	cl.ch <- []common.Node{encodedNode(t, "n", "192.0.2.1", "10.0.0.1")}
	cancel()
	require.NoError(t, waitErr(t, errc))
	assert.Empty(t, hosts.writes)
}

func Test_AgentCmd_loop_setupFailureDownsInterface(t *testing.T) {
	cl := &fakeCluster{ch: make(chan []common.Node)}
	wg := &fakeWG{upErr: errors.New("boom")}
	cancel, errc := runLoop(t, &AgentCmd{OverlayNet: testOverlay, NoEtcHosts: true}, cl, wg, &fakeHosts{})

	cl.ch <- []common.Node{encodedNode(t, "n", "192.0.2.1", "10.0.0.1")}
	cancel()
	require.NoError(t, waitErr(t, errc))
	assert.Equal(t, 2, wg.downs, "once after the failed setup, once on shutdown")
}

func Test_AgentCmd_loop_closedChannel(t *testing.T) {
	cl := &fakeCluster{ch: make(chan []common.Node)}
	_, errc := runLoop(t, &AgentCmd{}, cl, &fakeWG{}, &fakeHosts{})
	close(cl.ch)
	err := waitErr(t, errc)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "channel closed")
}
