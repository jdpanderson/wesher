package cluster

import (
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/jdpanderson/cheesecloth/trust"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testNode is a node with its own transport, for exercising the transport alone.
type testNode struct {
	id   *trust.Identity
	tr   *quicTransport
	addr string
}

func newTestNode(t *testing.T, id *trust.Identity, set *trust.Set) *testNode {
	t.Helper()
	tr, err := newQUICTransport(netip.MustParseAddr("127.0.0.1"), 0, id, set, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = tr.Shutdown() })
	return &testNode{id: id, tr: tr, addr: tr.udp.LocalAddr().String()}
}

// twoMembers builds root a and member b, each with its own copy of the records.
func twoMembers(t *testing.T) (a, b *testNode) {
	t.Helper()
	rootID, bID := testIdentity(t), testIdentity(t)
	recs := trust.Records{Admissions: []trust.Admission{
		trust.SelfAdmit(rootID, "a", time.Now()),
		trust.Admit(rootID, bID.Public(), bID.DHPublic(), "b", 2, time.Now()),
	}}
	setA, setB := trust.NewSet(rootID.Public()), trust.NewSet(rootID.Public())
	setA.Merge(recs)
	setB.Merge(recs)
	return newTestNode(t, rootID, setA), newTestNode(t, bID, setB)
}

// sendUntilConnected sends msg until a connection exists to carry it; the
// first sends are dropped while the transport connects, as UDP would drop them.
func sendUntilConnected(t *testing.T, from *testNode, to string, msg string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for from.tr.lookup(to) == nil {
		_, err := from.tr.WriteTo([]byte(msg), to)
		require.NoError(t, err)
		if time.Now().After(deadline) {
			t.Fatalf("never connected to %s", to)
		}
		time.Sleep(20 * time.Millisecond)
	}
	_, err := from.tr.WriteTo([]byte(msg), to)
	require.NoError(t, err)
}

// waitForgotten waits for n to drop its connection to addr.
func waitForgotten(t *testing.T, n *testNode, addr string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for n.tr.lookup(addr) != nil && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	assert.Nil(t, n.tr.lookup(addr), "connection to %s still present", addr)
}

// streamDies checks that a stream the peer will not accept fails on first use.
func streamDies(t *testing.T, conn net.Conn) {
	t.Helper()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = conn.Write([]byte("intrude"))
	_, err := conn.Read(make([]byte, 1))
	assert.Error(t, err, "peer must have closed the connection")
	_ = conn.Close()
}

func expectPacket(t *testing.T, n *testNode, want string) {
	t.Helper()
	select {
	case p := <-n.tr.PacketCh():
		assert.Equal(t, want, string(p.Buf))
	case <-time.After(3 * time.Second):
		t.Fatalf("packet %q not delivered", want)
	}
}

func Test_quicTransport_packetsAndStreams(t *testing.T) {
	a, b := twoMembers(t)

	// the first packet to an unknown address is dropped and starts a connection; packets flow once it is up
	assert.Nil(t, a.tr.lookup(b.addr))
	sendUntilConnected(t, a, b.addr, "ping")
	expectPacket(t, b, "ping")

	// the accepting side reuses the same connection in the other direction
	_, err := b.tr.WriteTo([]byte("pong"), a.addr)
	require.NoError(t, err)
	expectPacket(t, a, "pong")

	// oversized packets are refused rather than truncated
	_, err = a.tr.WriteTo(make([]byte, 65000), b.addr)
	assert.Error(t, err)

	// a stream a -> b on the same connection
	conn, err := a.tr.DialTimeout(b.addr, 2*time.Second)
	require.NoError(t, err)
	assert.Equal(t, b.addr, conn.RemoteAddr().String())
	go func() { _, _ = conn.Write([]byte("hello")); _ = conn.Close() }()
	select {
	case s := <-b.tr.StreamCh():
		buf := make([]byte, 5)
		_, err = io.ReadFull(s, buf)
		require.NoError(t, err)
		assert.Equal(t, "hello", string(buf))
		assert.Equal(t, a.addr, s.RemoteAddr().String())
		_ = s.Close()
	case <-time.After(3 * time.Second):
		t.Fatal("stream not delivered")
	}

	// a peer that shuts down takes its connection with it; dialling it anew fails
	_ = b.tr.Shutdown()
	waitForgotten(t, a, b.addr)
	_, err = a.tr.DialTimeout(b.addr, time.Second)
	assert.Error(t, err)
	_, err = a.tr.WriteTo([]byte("lost"), b.addr)
	assert.NoError(t, err, "packets to a dead peer are dropped, not failed")
	_, err = a.tr.DialTimeout("127.0.0.1:1", time.Second)
	assert.ErrorContains(t, err, "gossip to 127.0.0.1:1")
}

func Test_quicTransport_advertiseAddr(t *testing.T) {
	a, _ := twoMembers(t)
	ip, port, err := a.tr.FinalAdvertiseAddr("", 0)
	require.NoError(t, err)
	assert.Equal(t, a.addr, hostPortOf(ip.String(), port))
	ip, port, err = a.tr.FinalAdvertiseAddr("192.0.2.1", 7946)
	require.NoError(t, err)
	assert.Equal(t, "192.0.2.1:7946", hostPortOf(ip.String(), port))
	_, port, err = a.tr.FinalAdvertiseAddr("192.0.2.1", 0)
	require.NoError(t, err)
	assert.NotZero(t, port, "the bound port fills in")
	_, _, err = a.tr.FinalAdvertiseAddr("nonsense", 0)
	assert.Error(t, err)

	wild, err := newQUICTransport(netip.IPv4Unspecified(), 0, a.id, a.tr.set, nil)
	require.NoError(t, err)
	defer func() { _ = wild.Shutdown() }()
	_, _, err = wild.FinalAdvertiseAddr("", 0)
	assert.ErrorContains(t, err, "advertise address is required")
}

func hostPortOf(ip string, port int) string {
	return netip.AddrPortFrom(netip.MustParseAddr(ip), uint16(port)).String()
}

func Test_quicTransport_rejectsStrangers(t *testing.T) {
	rootID := testIdentity(t)
	set := trust.NewSet(rootID.Public())
	set.Merge(trust.Records{Admissions: []trust.Admission{trust.SelfAdmit(rootID, "a", time.Now())}})
	member := newTestNode(t, rootID, set)

	// stranger trusts a different root (itself) and "admits" the member in its own world
	strangerID := testIdentity(t)
	strangerSet := trust.NewSet(strangerID.Public())
	strangerSet.Merge(trust.Records{Admissions: []trust.Admission{
		trust.SelfAdmit(strangerID, "s", time.Now()),
		trust.Admit(strangerID, rootID.Public(), rootID.DHPublic(), "a", 2, time.Now()),
	}})
	stranger := newTestNode(t, strangerID, strangerSet)

	// TLS 1.3 rejects a client certificate after the client's handshake has
	// completed, so the dial itself may succeed; the stream must then be dead
	// and the member must never surface it.
	if conn, err := stranger.tr.DialTimeout(member.addr, 2*time.Second); err == nil {
		streamDies(t, conn)
	}
	select {
	case s := <-member.tr.StreamCh():
		t.Fatalf("member must not surface a stream from a non-member (%s)", s.RemoteAddr())
	case p := <-member.tr.PacketCh():
		t.Fatalf("member must not surface a packet from a non-member (%q)", p.Buf)
	case <-time.After(300 * time.Millisecond):
	}
	assert.Nil(t, member.tr.lookup(stranger.addr))

	// and a member refuses to talk to a stranger posing as a server
	_, err := member.tr.DialTimeout(stranger.addr, 2*time.Second)
	assert.ErrorContains(t, err, "not a member")
}

func Test_quicTransport_revocationCutsConnection(t *testing.T) {
	a, b := twoMembers(t)
	sendUntilConnected(t, a, b.addr, "ping")
	expectPacket(t, b, "ping")

	// a revokes b; b's next packet closes the connection instead of being delivered
	_, err := a.tr.set.AddRevocation(trust.Revoke(a.id, b.id.Public(), time.Now()))
	require.NoError(t, err)
	_, err = b.tr.WriteTo([]byte("still here?"), a.addr)
	require.NoError(t, err)
	select {
	case p := <-a.tr.PacketCh():
		t.Fatalf("packet from a revoked node delivered: %q", p.Buf)
	case <-time.After(300 * time.Millisecond):
	}
	waitForgotten(t, a, b.addr)
	if conn, err := b.tr.DialTimeout(a.addr, 2*time.Second); err == nil {
		streamDies(t, conn)
	}
	assert.Nil(t, a.tr.lookup(b.addr), "and b cannot come back")
}

func Test_quicTransport_oneConnectionPerPair(t *testing.T) {
	a, b := twoMembers(t)

	// both sides dial each other at once, several times over
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); _, _ = a.tr.DialTimeout(b.addr, 2*time.Second) }()
		go func() { defer wg.Done(); _, _ = b.tr.DialTimeout(a.addr, 2*time.Second) }()
	}
	wg.Wait()
	time.Sleep(200 * time.Millisecond) // closes propagate

	preferred := a.id.Public()
	if b.id.Public().String() < preferred.String() {
		preferred = b.id.Public()
	}
	a.tr.mu.Lock()
	ca := a.tr.conns[b.addr]
	a.tr.mu.Unlock()
	b.tr.mu.Lock()
	cb := b.tr.conns[a.addr]
	b.tr.mu.Unlock()
	require.NotNil(t, ca.conn)
	require.NotNil(t, cb.conn)
	assert.Equal(t, preferred, ca.client, "a kept the connection dialled by the smaller identity")
	assert.Equal(t, preferred, cb.client, "and so did b")
	assert.NoError(t, ca.conn.Context().Err())
	assert.NoError(t, cb.conn.Context().Err())

	// the survivor carries traffic both ways
	_, err := a.tr.WriteTo([]byte("ping"), b.addr)
	require.NoError(t, err)
	expectPacket(t, b, "ping")
	_, err = b.tr.WriteTo([]byte("pong"), a.addr)
	require.NoError(t, err)
	expectPacket(t, a, "pong")
}
