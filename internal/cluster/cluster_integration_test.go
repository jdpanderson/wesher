package cluster

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/hashicorp/memberlist"
	"github.com/jdpanderson/cheesecloth/internal/overlay"
	"github.com/jdpanderson/cheesecloth/internal/trust"
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

// rootCluster starts a new cluster whose root is this node.
func rootCluster(t *testing.T, name string) *Cluster {
	t.Helper()
	b, err := Load(name, true)
	require.NoError(t, err)
	b.InitRoot(name)
	c, err := New(Config{
		StateName: name, BindAddr: loopback, AdvertiseAddr: loopback, BindPort: freePort(t), OverlayNet: testOverlay,
		LocalNode: testNodeFor(t, name, b), Boot: b,
	})
	require.NoError(t, err)
	return c
}

// gossipAddr is the ip:port a cluster's peers reach it at.
func gossipAddr(c *Cluster) string { return c.enrolSrv.GossipAddr }

// enrolCluster enrols a new node with member and joins it to the gossip ring.
func enrolCluster(t *testing.T, member *Cluster, name string) *Cluster {
	t.Helper()
	token, err := member.Invite(time.Minute, 1)
	require.NoError(t, err)
	b, err := Load(name, true)
	require.NoError(t, err)
	w, err := Enrol(context.Background(), gossipAddr(member), token, b.Identity, name)
	require.NoError(t, err)
	require.Equal(t, member.Identity(), w.Member)
	b.Enrol(w.Root, w.Records)
	c, err := New(Config{
		StateName: name, BindAddr: loopback, AdvertiseAddr: loopback, BindPort: freePort(t), OverlayNet: testOverlay,
		LocalNode: testNodeFor(t, name, b), Boot: b,
	})
	require.NoError(t, err)
	require.NoError(t, c.Join([]string{w.GossipAddr}))
	return c
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

// useFastMemberlist swaps in the local-network memberlist timers for quick failure detection.
func useFastMemberlist(t *testing.T) {
	t.Helper()
	orig := newMemberlistConfig
	newMemberlistConfig = memberlist.DefaultLocalConfig
	t.Cleanup(func() { newMemberlistConfig = orig })
}

func Test_Cluster_enrolJoinLeave(t *testing.T) {
	useTempStatePaths(t)

	a := rootCluster(t, "a")
	defer a.Leave()
	chA := a.Members()

	b := enrolCluster(t, a, "b")
	drain(b.Members())

	members := waitMembers(t, chA, 1)
	assert.Equal(t, "b", members[0].Name)
	assert.Equal(t, "10.0.0.2", members[0].OverlayAddr.String())
	assert.Equal(t, testKey, members[0].PubKey)
	assert.Equal(t, b.Identity(), trust.PublicKey(members[0].Identity))
	assert.True(t, a.Trust().Valid(b.Identity()))
	assert.True(t, b.Trust().Valid(a.Identity()))

	b.Leave()
	waitMembers(t, chA, 0)

	// both persisted enough to restart unattended
	for _, name := range []string{"a", "b"} {
		st, err := loadState(name)
		require.NoError(t, err, name)
		require.NotNil(t, st.Root, name)
		assert.Equal(t, a.Identity(), *st.Root, name)
		assert.Len(t, st.Records.Admissions, 2, name)
	}
	boot, err := Load("b", false)
	require.NoError(t, err)
	assert.True(t, boot.Enrolled())
	assert.Equal(t, b.Identity(), boot.Identity.Public())
}

func Test_Cluster_rejectsUnenrolled(t *testing.T) {
	useTempStatePaths(t)
	a := rootCluster(t, "a")
	defer a.Leave()
	drain(a.Members())

	// a node rooted elsewhere knows a's address and identity but is not a member of a's cluster
	c := rootCluster(t, "c")
	defer c.Leave()
	err := c.Join([]string{gossipAddr(a)})
	require.Error(t, err)
	assert.Equal(t, 1, a.ml.Load().NumMembers(), "a must not have admitted c")
}

func Test_Cluster_revocation(t *testing.T) {
	useTempStatePaths(t)
	useFastMemberlist(t)
	a := rootCluster(t, "a")
	defer a.Leave()
	chA := a.Members()
	b := enrolCluster(t, a, "b")
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
	useTempStatePaths(t)
	useFastMemberlist(t)
	a := rootCluster(t, "a")
	defer a.Leave()
	chA := a.Members()
	b := enrolCluster(t, a, "b")
	defer b.Leave()
	chB := b.Members()
	waitMembers(t, chA, 1)
	waitMembers(t, chB, 1)

	// c is enrolled by b, not by the root, and joins via b; a must still accept it
	c := enrolCluster(t, b, "c")
	defer c.Leave()
	drain(c.Members())
	members := waitMembers(t, chA, 2)
	names := []string{members[0].Name, members[1].Name}
	assert.ElementsMatch(t, []string{"b", "c"}, names)
	assert.True(t, a.Trust().Valid(c.Identity()))
}

func Test_New_badBindAddr(t *testing.T) {
	useTempStatePaths(t)
	b, err := Load("a", true)
	require.NoError(t, err)
	b.InitRoot("a")
	bad := netip.MustParseAddr("192.0.2.1") // TEST-NET, not a local address
	_, err = New(Config{StateName: "a", BindAddr: bad, AdvertiseAddr: bad, BindPort: 0, OverlayNet: testOverlay,
		LocalNode: testNodeFor(t, "a", b), Boot: b})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "gossip transport")
}

func Test_New_notAMember(t *testing.T) {
	useTempStatePaths(t)
	b, err := Load("a", true)
	require.NoError(t, err)
	b.Root = testIdentity(t).Public() // pinned to a root that never admitted us
	_, err = New(Config{StateName: "a", OverlayNet: testOverlay, LocalNode: &overlay.Node{Name: "a"}, Boot: b})
	assert.ErrorContains(t, err, "not a member")
	_, err = New(Config{StateName: "a", LocalNode: &overlay.Node{Name: "a"}})
	assert.ErrorContains(t, err, "bootstrap and local node are required")
}

func Test_Cluster_Leave_closesMembers(t *testing.T) {
	useTempStatePaths(t)
	c := rootCluster(t, "a")
	ch := c.Members()
	assert.Panics(t, func() { c.Members() }, "one membership channel per cluster")

	c.Leave()
	c.Leave() // idempotent

	select {
	case _, ok := <-ch:
		assert.False(t, ok, "Members channel must be closed after Leave")
	case <-time.After(5 * time.Second):
		t.Fatal("Members channel not closed after Leave")
	}
}

func Test_Cluster_detectsFailedNode(t *testing.T) {
	useTempStatePaths(t)
	useFastMemberlist(t)
	a := rootCluster(t, "a")
	defer a.Leave()
	chA := a.Members()
	b := enrolCluster(t, a, "b")
	drain(b.Members())
	waitMembers(t, chA, 1)

	// crash b without leaving; a must eventually mark it dead
	require.NoError(t, b.ml.Load().Shutdown())
	close(b.done)
	b.routines.Wait()
	waitMembers(t, chA, 0)
}
