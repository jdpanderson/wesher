package cluster

import (
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/costela/wesher/common"
	"github.com/hashicorp/memberlist"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testKey = []byte("abcdefghijklmnopqrstuvwxyzABCDEF")

// freePort returns a TCP port that was free at call time; memberlist needs
// the same port for TCP and UDP, so this is best effort.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

// newTestCluster creates a cluster for a node called name; the state file is named after it too.
func newTestCluster(t *testing.T, name, bindAddr string, port int, overlay string) (*Cluster, *common.Node) {
	t.Helper()
	node := &common.Node{Name: name}
	node.OverlayAddr = netip.MustParseAddr(overlay)
	node.PubKey = "pubkey-" + name
	bind := netip.MustParseAddr(bindAddr)
	c, err := New(name, true, testKey, bind, bind, port, node)
	require.NoError(t, err)
	return c, node
}

func waitMembers(t *testing.T, ch <-chan []common.Node, want int) []common.Node {
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

func drain(ch <-chan []common.Node) {
	go func() {
		for range ch {
		}
	}()
}

func Test_Cluster_joinAndLeave(t *testing.T) {
	useTempStatePaths(t)
	port := freePort(t)

	a, _ := newTestCluster(t, "a", "127.0.0.1", port, "10.0.0.1")
	defer a.Leave()
	b, nodeB := newTestCluster(t, "b", "127.0.0.2", port, "10.0.0.2")

	chA := a.Members()
	drain(b.Members())

	require.NoError(t, a.Join(nil), "no addresses and no state is not an error")
	require.NoError(t, b.Join([]string{fmt.Sprintf("127.0.0.1:%d", port)}))

	members := waitMembers(t, chA, 1)
	require.NoError(t, members[0].DecodeMeta())
	assert.Equal(t, "b", members[0].Name)
	assert.Equal(t, nodeB.OverlayAddr, members[0].OverlayAddr)
	assert.Equal(t, nodeB.PubKey, members[0].PubKey)

	b.Leave()
	waitMembers(t, chA, 0)

	// state persisted for both sides
	for _, name := range []string{"a", "b"} {
		assert.Equal(t, testKey, loadState(name).ClusterKey, name)
	}
}

func Test_Cluster_joinFailure(t *testing.T) {
	useTempStatePaths(t)
	port := freePort(t)
	c, _ := newTestCluster(t, "a", "127.0.0.1", port, "10.0.0.1")
	defer c.Leave()

	err := c.Join([]string{fmt.Sprintf("127.0.0.9:%d", port)})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "joining cluster")
}

func Test_New_badBindAddr(t *testing.T) {
	useTempStatePaths(t)
	bad := netip.MustParseAddr("192.0.2.1") // TEST-NET, not a local address
	_, err := New("a", true, testKey, bad, bad, 0, &common.Node{Name: "a"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "creating memberlist")
}

// useFastMemberlist swaps in the local-network memberlist timers for quick failure detection.
func useFastMemberlist(t *testing.T) {
	t.Helper()
	orig := newMemberlistConfig
	newMemberlistConfig = memberlist.DefaultLocalConfig
	t.Cleanup(func() { newMemberlistConfig = orig })
}

func Test_Cluster_Leave_closesMembers(t *testing.T) {
	useTempStatePaths(t)
	c, _ := newTestCluster(t, "a", "127.0.0.1", freePort(t), "10.0.0.1")
	ch := c.Members()

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
	port := freePort(t)

	a, _ := newTestCluster(t, "a", "127.0.0.1", port, "10.0.0.1")
	defer a.Leave()
	b, _ := newTestCluster(t, "b", "127.0.0.2", port, "10.0.0.2")

	chA := a.Members()
	drain(b.Members())
	require.NoError(t, b.Join([]string{fmt.Sprintf("127.0.0.1:%d", port)}))
	waitMembers(t, chA, 1)

	// crash b without leaving; a must eventually mark it dead
	require.NoError(t, b.ml.Shutdown())
	close(b.done)
	b.routines.Wait()
	waitMembers(t, chA, 0)
}
