package cluster

import (
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/costela/wesher/common"
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
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func newTestCluster(t *testing.T, name, bindAddr string, port int, overlay string) (*Cluster, *common.Node) {
	t.Helper()
	c, err := New(name, true, testKey, bindAddr, port, true)
	require.NoError(t, err)

	node := &common.Node{Name: name}
	node.OverlayAddr = netip.MustParseAddr(overlay)
	node.PubKey = "pubkey-" + name
	c.Update(node)
	return c, node
}

func waitMembers(t *testing.T, ch <-chan []common.Node, want int) []common.Node {
	t.Helper()
	deadline := time.After(15 * time.Second)
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
	assert.Equal(t, "127.0.0.1", a.LocalName)
	assert.Equal(t, "a", a.Name())

	chA := a.Members()
	drain(b.Members())

	require.NoError(t, a.Join(nil), "no addresses and no state is not an error")
	require.NoError(t, b.Join([]string{fmt.Sprintf("127.0.0.1:%d", port)}))

	members := waitMembers(t, chA, 1)
	require.NoError(t, members[0].DecodeMeta())
	assert.Equal(t, "127.0.0.2", members[0].Name)
	assert.Equal(t, nodeB.OverlayAddr, members[0].OverlayAddr)
	assert.Equal(t, nodeB.PubKey, members[0].PubKey)

	b.Leave()
	waitMembers(t, chA, 0)

	// state persisted for both sides
	for _, name := range []string{"a", "b"} {
		s := &state{}
		loadState(s, name)
		assert.Equal(t, testKey, s.ClusterKey, name)
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
	_, err := New("a", true, testKey, "192.0.2.1", 0, false) // TEST-NET, not a local address
	require.Error(t, err)
	assert.Contains(t, err.Error(), "creating memberlist")
}
