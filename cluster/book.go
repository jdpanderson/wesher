package cluster

import (
	"net"
	"strconv"
	"sync"

	"github.com/jdpanderson/cheesecloth/trust"
)

// addrBook maps gossip addresses (ip:port) to node identities, so the
// transport knows whose key to encrypt a packet with.
type addrBook struct {
	mu sync.RWMutex
	m  map[string]trust.PublicKey
}

func newAddrBook() *addrBook { return &addrBook{m: map[string]trust.PublicKey{}} }

func (b *addrBook) set(addr string, id trust.PublicKey) {
	b.mu.Lock()
	b.m[addr] = id
	b.mu.Unlock()
}

func (b *addrBook) lookup(addr string) (trust.PublicKey, bool) {
	b.mu.RLock()
	id, ok := b.m[addr]
	b.mu.RUnlock()
	return id, ok
}

// hostPort formats an address the way memberlist does.
func hostPort(ip net.IP, port int) string {
	return net.JoinHostPort(ip.String(), strconv.Itoa(port))
}
