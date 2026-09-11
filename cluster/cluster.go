// Package cluster manages membership: a memberlist gossip ring whose transport
// authenticates nodes by identity, a signed admission set, and enrolment of new
// nodes with invitation tokens. See docs/membership.md.
package cluster

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/memberlist"
	"github.com/jdpanderson/cheesecloth/common"
	"github.com/jdpanderson/cheesecloth/enroll"
	"github.com/jdpanderson/cheesecloth/trust"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Config is what New needs.
type Config struct {
	Name          string       // state name; the wireguard interface in practice
	BindAddr      netip.Addr   // may be a wildcard
	AdvertiseAddr netip.Addr   // what other nodes are told to reach us at
	BindPort      int          // gossip and enrolment, UDP (QUIC)
	OverlayNet    netip.Prefix // overlay addresses are admission slots inside it
	LocalNode     *common.Node
	Boot          *Bootstrap // identity, trust and last known peers; owned by the cluster from here on
}

// Cluster represents a running cluster configuration
type Cluster struct {
	name      string
	ml        atomic.Pointer[memberlist.Memberlist]
	local     *common.Node
	id        *trust.Identity
	set       *trust.Set
	overlay   netip.Prefix
	tokens    *enroll.TokenStore
	queue     *memberlist.TransmitLimitedQueue
	enrolSrv  *enroll.Server
	boot      *Bootstrap
	stateMu   sync.Mutex // guards boot and its saving
	events    chan memberlist.NodeEvent
	changed   chan struct{}  // one-slot signal that the member list changed
	done      chan struct{}  // closed by Leave
	routines  sync.WaitGroup // forwardEvents and Members goroutines; Leave waits for them
	leaveOnce sync.Once
}

// newMemberlistConfig builds the base memberlist config; tests swap in faster timers.
var newMemberlistConfig = memberlist.DefaultWANConfig

// New creates a Cluster for an enrolled node and starts gossiping and accepting
// enrolments; it is ready to be joined.
func New(cfg Config) (*Cluster, error) {
	if cfg.Boot == nil || cfg.Boot.Identity == nil || cfg.LocalNode == nil {
		return nil, fmt.Errorf("cluster: bootstrap and local node are required")
	}
	id := cfg.Boot.Identity
	set := trust.NewSet(cfg.Boot.Root)
	set.Merge(cfg.Boot.Records)
	if !set.Valid(id.Public()) {
		return nil, fmt.Errorf("this node (%s) is not a member of the cluster rooted at %s", id.Public().Short(), cfg.Boot.Root.Short())
	}

	if want, err := assignedAddr(set, cfg.OverlayNet, id.Public()); err != nil {
		return nil, err
	} else if want != cfg.LocalNode.OverlayAddr {
		return nil, fmt.Errorf("local overlay address %s is not the assigned %s", cfg.LocalNode.OverlayAddr, want)
	}

	// bind our ephemeral wireguard key, overlay address and routes to our identity
	cfg.LocalNode.Identity = id.Public()
	cfg.LocalNode.Signature = id.Sign(trust.MetaDigest(cfg.LocalNode.Name, cfg.LocalNode.OverlayAddr, cfg.LocalNode.PubKey, cfg.LocalNode.AllowedIPs))

	c := &Cluster{
		name:    cfg.Name,
		local:   cfg.LocalNode,
		id:      id,
		set:     set,
		overlay: cfg.OverlayNet,
		tokens:  enroll.NewTokenStore(),
		events:  make(chan memberlist.NodeEvent, 16),
		changed: make(chan struct{}, 1),
		done:    make(chan struct{}),
		boot:    cfg.Boot,
	}
	c.queue = &memberlist.TransmitLimitedQueue{RetransmitMult: 3, NumNodes: func() int {
		if ml := c.ml.Load(); ml != nil {
			return ml.NumMembers()
		}
		return 1
	}}

	// enrolment shares the gossip listener under its own ALPN
	c.enrolSrv = &enroll.Server{
		Identity: id, Tokens: c.tokens, Root: cfg.Boot.Root, Admit: c.admit,
		GossipAddr: net.JoinHostPort(cfg.AdvertiseAddr.String(), strconv.Itoa(cfg.BindPort)),
	}
	logger := slog.NewLogLogger(slog.Default().Handler(), slog.LevelDebug)
	transport, err := newQUICTransport(cfg.BindAddr, cfg.BindPort, id, set, c.enrolSrv.Handle)
	if err != nil {
		return nil, err
	}

	mlConfig := newMemberlistConfig()
	mlConfig.Name = cfg.LocalNode.Name
	mlConfig.Logger = logger
	mlConfig.Transport = transport
	mlConfig.BindAddr = cfg.BindAddr.String()
	mlConfig.BindPort = cfg.BindPort
	mlConfig.AdvertiseAddr = cfg.AdvertiseAddr.String()
	mlConfig.AdvertisePort = cfg.BindPort
	mlConfig.UDPBufferSize = maxDatagram
	mlConfig.Delegate = c
	mlConfig.Conflict = c
	mlConfig.Events = &memberlist.ChannelEventDelegate{Ch: c.events}

	ml, err := memberlist.Create(mlConfig)
	if err != nil {
		_ = transport.Shutdown()
		return nil, fmt.Errorf("creating memberlist: %w", err)
	}
	c.ml.Store(ml)

	c.routines.Add(1)
	go c.forwardEvents()

	c.stateMu.Lock()
	c.saveState()
	c.stateMu.Unlock()
	return c, nil
}

// Identity is this node's identity.
func (c *Cluster) Identity() trust.PublicKey { return c.id.Public() }

// Trust is the membership set.
func (c *Cluster) Trust() *trust.Set { return c.set }

// Invite mints an enrolment token valid for ttl and uses joiners.
func (c *Cluster) Invite(ttl time.Duration, uses int) (string, error) {
	return c.tokens.Mint(ttl, uses)
}

// Revoke signs and distributes a revocation of id.
func (c *Cluster) Revoke(id trust.PublicKey) error {
	rev := trust.Revoke(c.id, id, time.Now())
	if _, err := c.set.AddRevocation(rev); err != nil {
		return err
	}
	c.broadcast(recordMsg{Revocation: &rev})
	c.stateMu.Lock()
	c.saveState()
	c.stateMu.Unlock()
	c.signalChanged() // the revoked node drops out of Members at once
	return nil
}

// admit is called by the enrolment server once a joiner has proven the token:
// it gives the joiner the lowest free overlay slot and signs its admission.
// Names identify nodes everywhere else, so one already held by another member
// is refused. Serialised under stateMu so two joiners cannot be handed the
// same slot.
func (c *Cluster) admit(joiner trust.PublicKey, dh trust.DHKey, name string) (trust.Admission, trust.Records, error) {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	if c.set.NameTaken(name, joiner) {
		return trust.Admission{}, trust.Records{}, fmt.Errorf("a member named %q already exists", name)
	}
	var host uint64
	if cur, ok := c.set.Lookup(joiner); ok && c.set.Valid(joiner) {
		host = cur.Host // an identity enrolling again keeps its address
	} else {
		var err error
		if host, err = c.set.FreeHost(common.MaxHost(c.overlay)); err != nil {
			return trust.Admission{}, trust.Records{}, fmt.Errorf("%w in %s", err, c.overlay)
		}
	}
	a := trust.Admit(c.id, joiner, dh, name, host, time.Now())
	if _, err := c.set.AddAdmission(a); err != nil {
		return trust.Admission{}, trust.Records{}, err
	}
	c.broadcast(recordMsg{Admission: &a})
	c.saveState()
	return a, c.set.Records(), nil
}

// saveState persists the bootstrap, logging rather than failing on error: the
// state only speeds up the next start. Callers hold stateMu.
func (c *Cluster) saveState() {
	c.boot.Records = c.set.Records()
	if err := c.boot.save(c.name); err != nil {
		slog.Warn("could not save cluster state", "path", statePath(c.name), "err", err)
	}
}

// assignedAddr is the overlay address id's admission entitles it to. It fails
// if id is not a member, the slot does not fit the overlay net, or another
// member holds the slot with a stronger claim (see trust.Set.HostConflict).
func assignedAddr(set *trust.Set, overlay netip.Prefix, id trust.PublicKey) (netip.Addr, error) {
	if !set.Valid(id) {
		return netip.Addr{}, fmt.Errorf("identity %s is not a member", id.Short())
	}
	adm, _ := set.Lookup(id)
	addr, ok := common.OverlayAddr(overlay, adm.Host)
	if !ok {
		return netip.Addr{}, fmt.Errorf("overlay slot %d of %s does not fit in %s", adm.Host, adm.Name, overlay)
	}
	if other, clash := set.HostConflict(id); clash {
		return netip.Addr{}, fmt.Errorf("overlay address %s of %s collides with %s, admitted earlier; %s must be enrolled again", addr, adm.Name, other.Name, adm.Name)
	}
	return addr, nil
}

// verifyMeta decodes a node's metadata and checks that a valid member signed
// it, that it claims the overlay address its admission assigns, and that its
// wireguard key parses. A node that passes can be installed as a peer as is.
func verifyMeta(set *trust.Set, overlay netip.Prefix, n *common.Node) (trust.PublicKey, error) {
	if err := n.DecodeMeta(); err != nil {
		return trust.PublicKey{}, err
	}
	id := trust.PublicKey(n.Identity)
	want, err := assignedAddr(set, overlay, id)
	if err != nil {
		return id, err
	}
	if n.OverlayAddr != want {
		return id, fmt.Errorf("%s claims overlay address %s but is assigned %s", n.Name, n.OverlayAddr, want)
	}
	if !trust.Verify(id, trust.MetaDigest(n.Name, n.OverlayAddr, n.PubKey, n.AllowedIPs), n.Signature) {
		return id, fmt.Errorf("metadata signature of %s does not verify", n.Name)
	}
	if _, err := wgtypes.ParseKey(n.PubKey); err != nil {
		return id, fmt.Errorf("wireguard key of %s: %w", n.Name, err)
	}
	return id, nil
}

// forwardEvents logs memberlist events about other nodes, learns their
// addresses, and coalesces the events into changed.
func (c *Cluster) forwardEvents() {
	defer c.routines.Done()
	for {
		var event memberlist.NodeEvent
		select {
		case <-c.done:
			return
		case event = <-c.events:
		}
		if event.Node.Name == c.local.Name {
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
		c.stateMu.Lock()
		for _, n := range c.boot.Peers {
			addrs = append(addrs, n.Addr.String())
		}
		c.stateMu.Unlock()
	}

	ml := c.ml.Load()
	if _, err := ml.Join(addrs); err != nil {
		return fmt.Errorf("joining cluster: %w", err)
	} else if len(addrs) > 0 && ml.NumMembers() < 2 {
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
		ml := c.ml.Load()
		if err := ml.Leave(10 * time.Second); err != nil {
			slog.Warn("could not announce leave to the cluster", "err", err)
		}
		if err := ml.Shutdown(); err != nil {
			slog.Warn("could not shut down memberlist", "err", err)
		}
		close(c.done)
		c.routines.Wait()
	})
}

// Members returns a channel that receives the current list of other verified
// nodes, metadata decoded, right away and then whenever the membership
// changes; bursts of changes may be coalesced into one snapshot. Nodes that
// fail verifyMeta are left out. Call it at most once. The channel is closed
// after Leave.
func (c *Cluster) Members() <-chan []common.Node {
	changes := make(chan []common.Node)
	c.signalChanged() // the first snapshot may well be empty; the interface still needs to come up

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

			if _, err := assignedAddr(c.set, c.overlay, c.id.Public()); err != nil {
				slog.Error("this node lost its overlay address; peers will drop it", "err", err)
			}
			ml := c.ml.Load()
			nodes := make([]common.Node, 0, ml.NumMembers())
			for _, n := range ml.Members() {
				if n.Name == c.local.Name {
					continue
				}
				node := common.Node{Name: n.Name, Addr: n.Addr, Meta: n.Meta}
				if _, err := verifyMeta(c.set, c.overlay, &node); err != nil {
					slog.Warn("ignoring node with unverified metadata", "name", n.Name, "addr", n.Addr, "err", err)
					continue
				}
				nodes = append(nodes, node)
			}
			c.stateMu.Lock()
			c.boot.Peers = nodes
			c.saveState()
			c.stateMu.Unlock()
			select {
			case changes <- slices.Clone(nodes):
			case <-c.done:
				return
			}
		}
	}()

	return changes
}

// --- memberlist.Delegate: node metadata and membership record distribution ---

var _ memberlist.Delegate = (*Cluster)(nil)
var _ memberlist.ConflictDelegate = (*Cluster)(nil)

// recordMsg is a broadcast carrying one membership record.
type recordMsg struct {
	Admission  *trust.Admission  `json:"admission,omitempty"`
	Revocation *trust.Revocation `json:"revocation,omitempty"`
}

// recordBroadcast implements memberlist.NamedBroadcast; a newer record for the
// same identity supersedes an older one still queued.
type recordBroadcast struct {
	name string
	msg  []byte
}

func (b recordBroadcast) Name() string                                { return b.name }
func (b recordBroadcast) Invalidates(other memberlist.Broadcast) bool { return false }
func (b recordBroadcast) Message() []byte                             { return b.msg }
func (b recordBroadcast) Finished()                                   {}

func (c *Cluster) broadcast(m recordMsg) {
	msg, err := json.Marshal(m)
	if err != nil {
		return
	}
	name := "adm:"
	switch {
	case m.Admission != nil:
		name += m.Admission.Identity.String()
	case m.Revocation != nil:
		name = "rev:" + m.Revocation.Identity.String()
	}
	c.queue.QueueBroadcast(recordBroadcast{name: name, msg: msg})
}

// NodeMeta implements memberlist.Delegate: our signed metadata.
func (c *Cluster) NodeMeta(limit int) []byte {
	encoded, err := c.local.EncodeMeta(limit)
	if err != nil {
		slog.Error("failed to encode local node", "err", err)
		return nil
	}
	return encoded
}

// NotifyMsg implements memberlist.Delegate: a record broadcast from a peer.
// Records that change our set are re-broadcast so they spread epidemically.
func (c *Cluster) NotifyMsg(b []byte) {
	var m recordMsg
	if err := json.Unmarshal(b, &m); err != nil {
		slog.Debug("ignoring undecodable broadcast", "err", err)
		return
	}
	changed := false
	switch {
	case m.Admission != nil:
		ok, err := c.set.AddAdmission(*m.Admission)
		if err != nil {
			slog.Warn("rejecting admission record", "identity", m.Admission.Identity.Short(), "err", err)
			return
		}
		changed = ok
		if ok {
			slog.Info("node admitted", "name", m.Admission.Name, "identity", m.Admission.Identity.Short(), "by", m.Admission.Admitter.Short())
		}
	case m.Revocation != nil:
		ok, err := c.set.AddRevocation(*m.Revocation)
		if err != nil {
			slog.Warn("rejecting revocation record", "identity", m.Revocation.Identity.Short(), "err", err)
			return
		}
		changed = ok
		if ok {
			slog.Warn("node revoked", "identity", m.Revocation.Identity.Short(), "by", m.Revocation.Revoker.Short())
		}
	default:
		return
	}
	if changed {
		c.broadcast(m)
		c.stateMu.Lock()
		c.saveState()
		c.stateMu.Unlock()
		c.signalChanged()
	}
}

// GetBroadcasts implements memberlist.Delegate.
func (c *Cluster) GetBroadcasts(overhead, limit int) [][]byte {
	return c.queue.GetBroadcasts(overhead, limit)
}

// LocalState implements memberlist.Delegate: the whole record set, for push/pull.
func (c *Cluster) LocalState(join bool) []byte {
	b, err := json.Marshal(c.set.Records())
	if err != nil {
		return nil
	}
	return b
}

// MergeRemoteState implements memberlist.Delegate: union in a peer's records.
func (c *Cluster) MergeRemoteState(buf []byte, join bool) {
	var rs trust.Records
	if err := json.Unmarshal(buf, &rs); err != nil {
		slog.Debug("ignoring undecodable remote state", "err", err)
		return
	}
	if n := c.set.Merge(rs); n > 0 {
		slog.Debug("merged membership records", "new", n)
		c.stateMu.Lock()
		c.saveState()
		c.stateMu.Unlock()
		c.signalChanged()
	}
}

// NotifyConflict implements memberlist.ConflictDelegate.
func (c *Cluster) NotifyConflict(existing, other *memberlist.Node) {
	slog.Error("node name conflict detected", "name", other.Name, "addr", other.Addr)
}

// signalChanged wakes the Members loop: a record change may admit or revoke a peer.
func (c *Cluster) signalChanged() {
	select {
	case c.changed <- struct{}{}:
	default:
	}
}
