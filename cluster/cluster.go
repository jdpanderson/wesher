package cluster

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/costela/wesher/common"
	"github.com/hashicorp/memberlist"
	"github.com/mattn/go-isatty"
)

// KeyLen is the fixed length of cluster keys, must be checked by callers
const KeyLen = 32

// Cluster represents a running cluster configuration
type Cluster struct {
	name      string
	ml        *memberlist.Memberlist
	localName string
	state     *state
	stateMu   sync.Mutex // guards state.Nodes and state.save
	events    chan memberlist.NodeEvent
	changed   chan struct{}  // one-slot signal that the member list changed
	done      chan struct{}  // closed by Leave
	routines  sync.WaitGroup // forwardEvents and Members goroutines; Leave waits for them
	leaveOnce sync.Once
}

// newMemberlistConfig builds the base memberlist config; tests swap in faster timers.
var newMemberlistConfig = memberlist.DefaultWANConfig

// New creates a Cluster that gossips localNode's name and metadata; it is ready to be joined.
// name identifies the persisted state (the wireguard interface name in practice).
// bindAddr may be a wildcard; advertiseAddr is what other nodes are told to reach us at.
func New(name string, init bool, clusterKey []byte, bindAddr, advertiseAddr netip.Addr, bindPort int, localNode *common.Node) (*Cluster, error) {
	state := &state{}
	if !init {
		state = loadState(name)
	}

	clusterKey, generated, err := computeClusterKey(state, clusterKey)
	if err != nil {
		return nil, fmt.Errorf("computing cluster key: %w", err)
	}
	if generated {
		// Print the key only on a terminal so it does not end up in logs; otherwise say where it is.
		if isatty.IsTerminal(os.Stdout.Fd()) {
			fmt.Printf("new cluster key generated: %s\n", base64.StdEncoding.EncodeToString(clusterKey))
		} else {
			slog.Warn("new cluster key generated; not printing because stdout is not a terminal",
				"hint", "wesher showkey --interface "+name)
		}
	}

	// memberlist delivers events while holding its node lock, so the receiver must never
	// call back into memberlist: forwardEvents only logs and signals changed. The small
	// buffer absorbs events still in flight after Leave stops the forwarder.
	events := make(chan memberlist.NodeEvent, 16)

	delegate := &delegateNode{localNode}
	mlConfig := newMemberlistConfig()
	mlConfig.Name = localNode.Name
	mlConfig.Logger = slog.NewLogLogger(slog.Default().Handler(), slog.LevelDebug)
	mlConfig.SecretKey = clusterKey
	mlConfig.BindAddr = bindAddr.String()
	mlConfig.BindPort = bindPort
	mlConfig.AdvertiseAddr = advertiseAddr.String()
	mlConfig.AdvertisePort = bindPort
	mlConfig.Delegate = delegate
	mlConfig.Conflict = delegate
	mlConfig.Events = &memberlist.ChannelEventDelegate{Ch: events}

	ml, err := memberlist.Create(mlConfig)
	if err != nil {
		return nil, fmt.Errorf("creating memberlist: %w", err)
	}

	c := &Cluster{
		name:      name,
		ml:        ml,
		localName: localNode.Name,
		events:    events,
		changed:   make(chan struct{}, 1),
		done:      make(chan struct{}),
		state:     state,
	}
	c.routines.Add(1)
	go c.forwardEvents()

	return c, nil
}

// saveState persists the state, logging rather than failing on error: the
// state only speeds up the next start. Callers hold stateMu.
func (c *Cluster) saveState() {
	if err := c.state.save(c.name); err != nil {
		slog.Warn("could not save cluster state", "path", statePath(c.name), "err", err)
	}
}

// forwardEvents logs memberlist events about other nodes and coalesces them into changed.
func (c *Cluster) forwardEvents() {
	defer c.routines.Done()
	for {
		var event memberlist.NodeEvent
		select {
		case <-c.done:
			return
		case event = <-c.events:
		}
		if event.Node.Name == c.localName {
			continue
		}
		switch event.Event {
		case memberlist.NodeJoin:
			slog.Info("node joined", "name", event.Node.Name, "addr", event.Node.Addr)
		case memberlist.NodeUpdate:
			slog.Info("node updated", "name", event.Node.Name, "addr", event.Node.Addr)
		case memberlist.NodeLeave:
			slog.Info("node left", "name", event.Node.Name, "addr", event.Node.Addr)
		}
		select {
		case c.changed <- struct{}{}:
		default: // a signal is already pending
		}
	}
}

// Join tries to join the cluster by contacting provided addresses
// Provided addresses are passed as is, if no address is provided, known
// cluster nodes are contacted instead.
// Joining fail if none of the provided addresses or none of the known
// nodes can be joined.
func (c *Cluster) Join(addrs []string) error {
	if len(addrs) == 0 {
		for _, n := range c.state.Nodes {
			addrs = append(addrs, n.Addr.String())
		}
	}

	if _, err := c.ml.Join(addrs); err != nil {
		return fmt.Errorf("joining cluster: %w", err)
	} else if len(addrs) > 0 && c.ml.NumMembers() < 2 {
		return fmt.Errorf("could not join to any of the provided addresses")
	}

	return nil
}

// Leave saves the current state, leaves the cluster and stops Members. Safe to call more than once.
func (c *Cluster) Leave() {
	c.leaveOnce.Do(func() {
		c.stateMu.Lock()
		c.saveState()
		c.stateMu.Unlock()
		if err := c.ml.Leave(10 * time.Second); err != nil {
			slog.Warn("could not announce leave to the cluster", "err", err)
		}
		if err := c.ml.Shutdown(); err != nil {
			slog.Warn("could not shut down memberlist", "err", err)
		}
		close(c.done)
		c.routines.Wait()
	})
}

// Members returns a channel that receives the current list of other nodes
// whenever the membership changes; bursts of changes may be coalesced into
// one snapshot. Call it at most once. The channel is closed after Leave.
func (c *Cluster) Members() <-chan []common.Node {
	changes := make(chan []common.Node)

	c.routines.Add(1)
	go func() {
		defer c.routines.Done()
		defer close(changes)
		for {
			select {
			case <-c.done:
				return
			case <-c.changed:
			}

			nodes := make([]common.Node, 0, c.ml.NumMembers())
			for _, n := range c.ml.Members() {
				if n.Name == c.localName {
					continue
				}
				nodes = append(nodes, common.Node{
					Name: n.Name,
					Addr: n.Addr,
					Meta: n.Meta,
				})
			}
			c.stateMu.Lock()
			c.state.Nodes = nodes
			c.saveState()
			c.stateMu.Unlock()
			select {
			case changes <- slices.Clone(nodes): // consumer decodes meta in place
			case <-c.done:
				return
			}
		}
	}()

	return changes
}

// computeClusterKey settles on the provided key, else the stored one, else a
// fresh random key, and records it in state. generated reports the last case.
func computeClusterKey(state *state, clusterKey []byte) (key []byte, generated bool, err error) {
	if len(clusterKey) == 0 {
		clusterKey = state.ClusterKey
	}
	if len(clusterKey) == 0 {
		clusterKey = make([]byte, KeyLen)
		if _, err := rand.Read(clusterKey); err != nil {
			return nil, false, fmt.Errorf("reading random source: %w", err)
		}
		generated = true
	}
	state.ClusterKey = clusterKey
	return clusterKey, generated, nil
}
