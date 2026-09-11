package cluster

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/hashicorp/memberlist"
	"github.com/jdpanderson/cheesecloth/internal/overlay"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// freePort returns a TCP port that was free at call time; memberlist needs
// the same port for TCP and UDP, so this is best effort.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

var testOverlay = netip.MustParsePrefix("10.0.0.0/8")

// testNodeFor builds the local node for b at the overlay address its admission assigns.
func testNodeFor(t *testing.T, name string, b *Bootstrap) *overlay.Node {
	t.Helper()
	host, err := b.Host()
	require.NoError(t, err)
	addr, ok := overlay.Addr(testOverlay, host)
	require.True(t, ok)
	node := &overlay.Node{Name: name}
	node.OverlayAddr = addr
	node.PubKey = testKey
	return node
}

// loopback is where every test node binds, each on its own port.
var loopback = netip.MustParseAddr("127.0.0.1")

// fastMemberlist is the local-network memberlist profile, for quick failure detection in tests.
func fastMemberlist(c *Config) { c.Memberlist = memberlist.DefaultLocalConfig }

// rootCluster starts a new cluster whose root is this node, with state under dir.
func rootCluster(t *testing.T, dir, name string, opts ...func(*Config)) *Cluster {
	t.Helper()
	b, err := Load(dir, name, true)
	require.NoError(t, err)
	b.InitRoot(name)
	cfg := Config{
		StateDir: dir, StateName: name, BindAddr: loopback, AdvertiseAddr: loopback, BindPort: freePort(t), OverlayNet: testOverlay,
		LocalNode: testNodeFor(t, name, b), Boot: b,
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	c, err := New(cfg)
	require.NoError(t, err)
	return c
}

// gossipAddr is the ip:port a cluster's peers reach it at.
func gossipAddr(c *Cluster) string { return c.enrolSrv.GossipAddr }

// enrolCluster enrols a new node with member and joins it to the gossip ring.
func enrolCluster(t *testing.T, dir string, member *Cluster, name string, opts ...func(*Config)) *Cluster {
	t.Helper()
	token, err := member.Invite(time.Minute, 1)
	require.NoError(t, err)
	b, err := Load(dir, name, true)
	require.NoError(t, err)
	w, memberID, err := Enrol(context.Background(), gossipAddr(member), token, b.Identity, name)
	require.NoError(t, err)
	require.Equal(t, member.Identity(), memberID)
	b.Enrol(w.Root, w.Records)
	cfg := Config{
		StateDir: dir, StateName: name, BindAddr: loopback, AdvertiseAddr: loopback, BindPort: freePort(t), OverlayNet: testOverlay,
		LocalNode: testNodeFor(t, name, b), Boot: b,
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	c, err := New(cfg)
	require.NoError(t, err)
	require.NoError(t, c.Join([]string{w.GossipAddr}))
	return c
}

// Peers are remembered by address alone; a restarted node rejoins them on the
// cluster port, which is the one it was started with, not memberlist's default.
func Test_Cluster_Join_rememberedPeers(t *testing.T) {
	dir := useTempStatePaths(t)
	a := rootCluster(t, dir, "a")
	defer a.Leave()
	chA := a.Members()

	// b shares a's port on another loopback address, as real nodes share the cluster port
	other := netip.MustParseAddr("127.0.0.2")
	samePort := func(cfg *Config) { cfg.BindAddr, cfg.AdvertiseAddr, cfg.BindPort = other, other, a.port }
	b := enrolCluster(t, dir, a, "b", samePort)
	waitMembers(t, b.Members(), 1) // a is now remembered
	waitMembers(t, chA, 1)
	b.Leave()
	waitMembers(t, chA, 0)

	// b restarts from its state: no addresses given, only the remembered a
	boot, err := Load(dir, "b", false)
	require.NoError(t, err)
	require.Len(t, boot.Peers, 1)
	cfg := Config{StateDir: dir, StateName: "b", OverlayNet: testOverlay, LocalNode: testNodeFor(t, "b", boot), Boot: boot}
	samePort(&cfg)
	b, err = New(cfg)
	require.NoError(t, err)
	defer b.Leave()
	drain(b.Members())
	require.NoError(t, b.Join(nil))
	assert.Equal(t, "b", waitMembers(t, chA, 1)[0].Name)
}

func waitMembers(t *testing.T, ch <-chan []overlay.Node, want int) []overlay.Node {
	t.Helper()
	deadline := time.After(30 * time.Second)
	for {
		select {
		case nodes := <-ch:
			if len(nodes) == want {
				return nodes
			}
		case <-deadline:
			t.Fatalf("timed out waiting for %d members", want)
		}
	}
}

func drain(ch <-chan []overlay.Node) {
	go func() {
		for range ch {
		}
	}()
}

func Test_Cluster_enrolJoinLeave(t *testing.T) {
	dir := useTempStatePaths(t)

	a := rootCluster(t, dir, "a")
	defer a.Leave()
	chA := a.Members()

	b := enrolCluster(t, dir, a, "b")
	drain(b.Members())

	members := waitMembers(t, chA, 1)
	assert.Equal(t, "b", members[0].Name)
	assert.Equal(t, "10.0.0.2", members[0].OverlayAddr.String())
	assert.Equal(t, testKey, members[0].PubKey)
	assert.Equal(t, b.Identity(), members[0].Identity)
	assert.True(t, a.Trust().Valid(b.Identity()))
	assert.True(t, b.Trust().Valid(a.Identity()))

	b.Leave()
	waitMembers(t, chA, 0)

	// both persisted enough to restart unattended
	for _, name := range []string{"a", "b"} {
		st, err := loadState(statePath(dir, name))
		require.NoError(t, err, name)
		require.NotNil(t, st.Root, name)
		assert.Equal(t, a.Identity(), *st.Root, name)
		assert.Len(t, st.Records.Admissions, 2, name)
	}
	boot, err := Load(dir, "b", false)
	require.NoError(t, err)
	assert.True(t, boot.Enrolled())
	assert.Equal(t, b.Identity(), boot.Identity.Public())
}

func Test_Cluster_rejectsUnenrolled(t *testing.T) {
	dir := useTempStatePaths(t)
	a := rootCluster(t, dir, "a")
	defer a.Leave()
	drain(a.Members())

	// a node rooted elsewhere knows a's address and identity but is not a member of a's cluster
	c := rootCluster(t, dir, "c")
	defer c.Leave()
	err := c.Join([]string{gossipAddr(a)})
	require.Error(t, err)
	assert.Equal(t, 1, a.ml.Load().NumMembers(), "a must not have admitted c")
}

func Test_Cluster_revocation(t *testing.T) {
	dir := useTempStatePaths(t)
	a := rootCluster(t, dir, "a", fastMemberlist)
	defer a.Leave()
	chA := a.Members()
	b := enrolCluster(t, dir, a, "b", fastMemberlist)
	defer b.Leave()
	chB := b.Members()
	waitMembers(t, chA, 1)
	waitMembers(t, chB, 1)

	require.NoError(t, a.Revoke(b.Identity()))
	waitMembers(t, chA, 0)
	assert.False(t, a.Trust().Valid(b.Identity()))
	// a no longer talks to b at all, so b sees a fail and loses its peer
	waitMembers(t, chB, 0)
}

func Test_Cluster_recordsSpreadTransitively(t *testing.T) {
	dir := useTempStatePaths(t)
	a := rootCluster(t, dir, "a", fastMemberlist)
	defer a.Leave()
	chA := a.Members()
	b := enrolCluster(t, dir, a, "b", fastMemberlist)
	defer b.Leave()
	chB := b.Members()
	waitMembers(t, chA, 1)
	waitMembers(t, chB, 1)

	// c is enrolled by b, not by the root, and joins via b; a must still accept it
	c := enrolCluster(t, dir, b, "c", fastMemberlist)
	defer c.Leave()
	drain(c.Members())
	members := waitMembers(t, chA, 2)
	names := []string{members[0].Name, members[1].Name}
	assert.ElementsMatch(t, []string{"b", "c"}, names)
	assert.True(t, a.Trust().Valid(c.Identity()))
}

func Test_New_badBindAddr(t *testing.T) {
	dir := useTempStatePaths(t)
	b, err := Load(dir, "a", true)
	require.NoError(t, err)
	b.InitRoot("a")
	bad := netip.MustParseAddr("192.0.2.1") // TEST-NET, not a local address
	_, err = New(Config{StateDir: dir, StateName: "a", BindAddr: bad, AdvertiseAddr: bad, BindPort: 0, OverlayNet: testOverlay,
		LocalNode: testNodeFor(t, "a", b), Boot: b})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "gossip transport")
}

func Test_New_notAMember(t *testing.T) {
	dir := useTempStatePaths(t)
	b, err := Load(dir, "a", true)
	require.NoError(t, err)
	b.Root = testIdentity(t).Public() // pinned to a root that never admitted us
	_, err = New(Config{StateDir: dir, StateName: "a", OverlayNet: testOverlay, LocalNode: &overlay.Node{Name: "a"}, Boot: b})
	assert.ErrorContains(t, err, "not a member")
	_, err = New(Config{StateDir: dir, StateName: "a", LocalNode: &overlay.Node{Name: "a"}})
	assert.ErrorContains(t, err, "bootstrap and local node are required")
}

func Test_Cluster_Leave_closesMembers(t *testing.T) {
	dir := useTempStatePaths(t)
	c := rootCluster(t, dir, "a")
	ch := c.Members()
	second := c.Members()
	for _, sub := range []<-chan []overlay.Node{ch, second} {
		select {
		case peers := <-sub:
			assert.Empty(t, peers, "every subscriber gets a first snapshot")
		case <-time.After(5 * time.Second):
			t.Fatal("no first snapshot")
		}
	}
	c.signalChanged()
	c.signalChanged() // a subscriber that does not read keeps only the latest snapshot
	time.Sleep(100 * time.Millisecond)
	assert.LessOrEqual(t, len(second), 1)

	c.Leave()
	c.Leave() // idempotent

	// a snapshot still buffered is delivered, then every subscriber's channel is closed
	for _, sub := range []<-chan []overlay.Node{ch, second} {
		deadline := time.After(5 * time.Second)
		for closed := false; !closed; {
			select {
			case _, ok := <-sub:
				closed = !ok
			case <-deadline:
				t.Fatal("Members channel not closed after Leave")
			}
		}
	}
}

func Test_Cluster_detectsFailedNode(t *testing.T) {
	dir := useTempStatePaths(t)
	a := rootCluster(t, dir, "a", fastMemberlist)
	defer a.Leave()
	chA := a.Members()
	b := enrolCluster(t, dir, a, "b", fastMemberlist)
	drain(b.Members())
	waitMembers(t, chA, 1)

	// crash b without leaving; a must eventually mark it dead
	require.NoError(t, b.ml.Load().Shutdown())
	close(b.done)
	b.routines.Wait()
	waitMembers(t, chA, 0)
}
