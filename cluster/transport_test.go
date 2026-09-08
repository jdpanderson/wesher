package cluster

import (
	"log"
	"net"
	"testing"
	"time"

	"github.com/hashicorp/memberlist"
	"github.com/jdpanderson/wesher/trust"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testNode is a node with its own transport, for exercising the transport alone.
type testNode struct {
	id   *trust.Identity
	tr   *secureTransport
	addr string
}

func newTestNode(t *testing.T, id *trust.Identity, set *trust.Set, book *addrBook) *testNode {
	t.Helper()
	inner, err := memberlist.NewNetTransport(&memberlist.NetTransportConfig{
		BindAddrs: []string{"127.0.0.1"}, BindPort: 0, Logger: log.New(nopWriter{}, "", 0),
	})
	require.NoError(t, err)
	tr, err := newSecureTransport(inner, id, set, book)
	require.NoError(t, err)
	t.Cleanup(func() { _ = tr.Shutdown() })
	return &testNode{id: id, tr: tr, addr: hostPort(net.ParseIP("127.0.0.1"), inner.GetAutoBindPort())}
}

type nopWriter struct{}

func (nopWriter) Write(p []byte) (int, error) { return len(p), nil }

func Test_secureTransport_packetsAndStreams(t *testing.T) {
	// a is root, b admitted by a; each has its own view of the same records
	rootID, bID := testIdentity(t), testIdentity(t)
	recs := trust.Records{Admissions: []trust.Admission{
		trust.SelfAdmit(rootID, "a", time.Now()),
		trust.Admit(rootID, bID.Public(), bID.DHPublic(), "b", time.Now()),
	}}
	setA, setB := trust.NewSet(rootID.Public()), trust.NewSet(rootID.Public())
	setA.Merge(recs)
	setB.Merge(recs)
	bookA, bookB := newAddrBook(), newAddrBook()
	a := newTestNode(t, rootID, setA, bookA)
	b := newTestNode(t, bID, setB, bookB)
	bookA.set(b.addr, bID.Public())
	bookB.set(a.addr, rootID.Public())

	// a -> b packet
	_, err := a.tr.WriteTo([]byte("ping"), b.addr)
	require.NoError(t, err)
	select {
	case p := <-b.tr.PacketCh():
		assert.Equal(t, "ping", string(p.Buf))
		assert.Equal(t, a.addr, p.From.String())
	case <-time.After(2 * time.Second):
		t.Fatal("packet not delivered")
	}
	// b learned a's identity from the packet; b -> a works even without a prior book entry check
	_, err = b.tr.WriteTo([]byte("pong"), a.addr)
	require.NoError(t, err)
	select {
	case p := <-a.tr.PacketCh():
		assert.Equal(t, "pong", string(p.Buf))
	case <-time.After(2 * time.Second):
		t.Fatal("packet not delivered")
	}

	// unknown destination
	_, err = a.tr.WriteTo([]byte("x"), "127.0.0.1:1")
	assert.ErrorContains(t, err, "no identity known")

	// stream a -> b with mutual TLS
	conn, err := a.tr.DialTimeout(b.addr, 2*time.Second)
	require.NoError(t, err)
	go func() { _, _ = conn.Write([]byte("hello")); _ = conn.Close() }()
	select {
	case s := <-b.tr.StreamCh():
		buf := make([]byte, 5)
		_, err := s.Read(buf)
		require.NoError(t, err)
		assert.Equal(t, "hello", string(buf))
		_ = s.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("stream not delivered")
	}
}

func Test_secureTransport_rejectsStrangers(t *testing.T) {
	rootID := testIdentity(t)
	set := trust.NewSet(rootID.Public())
	set.Merge(trust.Records{Admissions: []trust.Admission{trust.SelfAdmit(rootID, "a", time.Now())}})
	member := newTestNode(t, rootID, set, newAddrBook())

	// stranger trusts a different root (itself) and knows the member's address and identity
	strangerID := testIdentity(t)
	strangerSet := trust.NewSet(strangerID.Public())
	strangerSet.Merge(trust.Records{Admissions: []trust.Admission{
		trust.SelfAdmit(strangerID, "s", time.Now()),
		trust.Admit(strangerID, rootID.Public(), rootID.DHPublic(), "a", time.Now()), // it "admits" the member in its own world
	}})
	stranger := newTestNode(t, strangerID, strangerSet, newAddrBook())
	stranger.tr.book.set(member.addr, rootID.Public())

	_, err := stranger.tr.WriteTo([]byte("intrude"), member.addr)
	require.NoError(t, err, "the stranger can send")
	select {
	case p := <-member.tr.PacketCh():
		t.Fatalf("member must drop packets from non-members, got %q", p.Buf)
	case <-time.After(500 * time.Millisecond):
	}

	// TLS 1.3 reports client-certificate rejection to the client only on its next
	// read, so the dial itself may succeed; the member must still never surface
	// the stream, and the stranger's connection must be dead.
	if conn, dialErr := stranger.tr.DialTimeout(member.addr, 2*time.Second); dialErr == nil {
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		_, _ = conn.Write([]byte("intrude"))
		_, readErr := conn.Read(make([]byte, 1))
		assert.Error(t, readErr, "member must have closed the stranger's stream")
		_ = conn.Close()
	}
	select {
	case s := <-member.tr.StreamCh():
		t.Fatalf("member must not surface a stream from a non-member (%s)", s.RemoteAddr())
	case <-time.After(500 * time.Millisecond):
	}

	// and a member refuses to talk to a stranger posing as a server
	member.tr.book.set(stranger.addr, stranger.id.Public())
	_, err = member.tr.WriteTo([]byte("x"), stranger.addr)
	assert.ErrorContains(t, err, "not a member")
	_, err = member.tr.DialTimeout(stranger.addr, 2*time.Second)
	assert.Error(t, err)
}
