package cluster

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_addrBook(t *testing.T) {
	b := newAddrBook()
	_, ok := b.lookup("192.0.2.1:7946")
	assert.False(t, ok)

	id := testIdentity(t).Public()
	b.set("192.0.2.1:7946", id)
	got, ok := b.lookup("192.0.2.1:7946")
	require.True(t, ok)
	assert.Equal(t, id, got)

	other := testIdentity(t).Public()
	b.set("192.0.2.1:7946", other) // a re-enrolled node at the same address replaces the entry
	got, _ = b.lookup("192.0.2.1:7946")
	assert.Equal(t, other, got)
}

func Test_hostPort(t *testing.T) {
	assert.Equal(t, "192.0.2.1:7946", hostPort(net.ParseIP("192.0.2.1"), 7946))
	assert.Equal(t, "[2001:db8::1]:7946", hostPort(net.ParseIP("2001:db8::1"), 7946))
}
