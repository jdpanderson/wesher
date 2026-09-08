package cluster

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
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
	done      chan struct{}  // closed by Leave
	members   sync.WaitGroup // Members goroutines; Leave waits for them
	leaveOnce sync.Once
}

// newMemberlistConfig builds the base memberlist config; tests swap in faster timers.
var newMemberlistConfig = memberlist.DefaultWANConfig

// New creates a Cluster that gossips localNode's name and metadata; it is ready to be joined.
// name identifies the persisted state (the wireguard interface name in practice).
func New(name string, init bool, clusterKey []byte, bindAddr string, bindPort int, localNode *common.Node) (*Cluster, error) {
	state := &state{}
	if !init {
		state = loadState(name)
	}

	clusterKey, err := computeClusterKey(state, clusterKey)
	if err != nil {
		return nil, fmt.Errorf("computing cluster key: %w", err)
	}

	// The big channel buffer is a work-around for https://github.com/hashicorp/memberlist/issues/23
	// More than this many simultaneous events will deadlock cluster.members()
	events := make(chan memberlist.NodeEvent, 100)

	delegate := &delegateNode{localNode}
	mlConfig := newMemberlistConfig()
	mlConfig.Name = localNode.Name
	mlConfig.Logger = slog.NewLogLogger(slog.Default().Handler(), slog.LevelDebug)
	mlConfig.SecretKey = clusterKey
	mlConfig.BindAddr = bindAddr
	mlConfig.BindPort = bindPort
	mlConfig.AdvertisePort = bindPort
	mlConfig.Delegate = delegate
	mlConfig.Conflict = delegate
	mlConfig.Events = &memberlist.ChannelEventDelegate{Ch: events}

	ml, err := memberlist.Create(mlConfig)
	if err != nil {
		return nil, fmt.Errorf("creating memberlist: %w", err)
	}

	return &Cluster{
		name:      name,
		ml:        ml,
		localName: localNode.Name,
		events:    events,
		done:      make(chan struct{}),
		state:     state,
	}, nil
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
		c.state.save(c.name) // nolint: errcheck // opportunistic
		c.stateMu.Unlock()
		c.ml.Leave(10 * time.Second) // nolint: errcheck
		c.ml.Shutdown()              // nolint: errcheck
		close(c.done)
		c.members.Wait()
	})
}

// Members provides a channel notifying of cluster changes
// Everytime a change happens inside the cluster (except for local changes),
// the updated list of cluster nodes is pushed to the channel.
// The channel is closed after Leave.
func (c *Cluster) Members() <-chan []common.Node {
	changes := make(chan []common.Node)

	c.members.Add(1)
	go func() {
		defer c.members.Done()
		defer close(changes)
		for {
			var event memberlist.NodeEvent
			select {
			case <-c.done:
				return
			case event = <-c.events:
			}
			if event.Node.Name == c.localName {
				// ignore events about ourselves
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
			c.state.save(c.name) // nolint: errcheck // opportunistic
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

func computeClusterKey(state *state, clusterKey []byte) ([]byte, error) {
	if len(clusterKey) == 0 {
		clusterKey = state.ClusterKey
	}

	if len(clusterKey) == 0 {
		clusterKey = make([]byte, KeyLen)

		if _, err := rand.Read(clusterKey); err != nil {
			return nil, fmt.Errorf("reading random source: %w", err)
		}

		// TODO: refactor this into subcommand ("showkey"?)
		if isatty.IsTerminal(os.Stdout.Fd()) {
			fmt.Printf("new cluster key generated: %s\n", base64.StdEncoding.EncodeToString(clusterKey))
		}
	}

	state.ClusterKey = clusterKey

	return clusterKey, nil
}
