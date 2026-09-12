package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/cenkalti/backoff/v6"
	"github.com/jdpanderson/cheesecloth/internal/cluster"
	"github.com/jdpanderson/cheesecloth/internal/control"
	"github.com/jdpanderson/cheesecloth/internal/enrol"
	"github.com/jdpanderson/cheesecloth/internal/notify"
	"github.com/jdpanderson/cheesecloth/internal/overlay"
	"github.com/jdpanderson/cheesecloth/internal/trust"
	"github.com/jdpanderson/cheesecloth/internal/wg"
)

// AgentCmd is the long-running daemon: it joins the cluster and keeps the
// wireguard interface and /etc/hosts in step with the membership.
type AgentCmd struct {
	Join          []string       `help:"comma separated list of hostnames or IP addresses of existing cluster members; if not provided, will attempt resuming any known state or otherwise wait for further members."`
	JoinKey       string         `help:"invitation token from 'cheesecloth invite' on a member, needed only the first time this node joins"`
	Init          bool           `help:"start a new cluster with this node as its root; any known state from previous runs will be forgotten"`
	BindAddr      netip.Addr     `help:"address to bind for cluster membership traffic; 0.0.0.0 or :: binds every interface of that family and advertises one of its addresses. The address family decides whether the cluster runs over IPv4 or IPv6" default:"0.0.0.0"`
	ClusterPort   int            `help:"UDP port used for membership gossip and enrolment (QUIC); must be the same across cluster" default:"7946"`
	WireguardPort int            `help:"port used for wireguard traffic (UDP); must be the same across cluster" default:"51820"`
	OverlayNet    netip.Prefix   `help:"the network in which to allocate addresses for the overlay mesh network (CIDR format); must be the same across cluster" default:"10.0.0.0/8"`
	AllowedIPs    []netip.Prefix `name:"allowed-ips" help:"extra networks reachable through this node (CIDR, comma separated); peers route them over the mesh via this node, which must forward. Must not overlap --overlay-net"`
	Interface     string         `help:"name of the wireguard interface to create and manage" default:"${default_interface}"`
	MTU           int            `help:"MTU of the wireguard interface" default:"1420"`
	// PersistentKeepalive is a time.Duration so kong accepts "25s"; 0 disables it.
	PersistentKeepalive time.Duration `help:"interval at which peers send keepalives, to keep NAT mappings open (e.g. 25s); 0 disables" default:"0"`
	NoEtcHosts          bool          `help:"disable writing of entries to /etc/hosts"`
	Userspace           bool          `help:"run wireguard inside the agent instead of the kernel module; the default wherever the kernel has none"`
	ControlSocket       string        `help:"unix socket for 'cheesecloth invite' and 'cheesecloth revoke' (default ${default_socket_dir}/<interface>.sock)"`

	addrs    func(skip string) []net.Addr // lists this host's candidate addresses; nil means the interfaces
	stateDir string                       // where the cluster state is kept; empty means cluster.DefaultDir
}

// state is the directory this node's cluster state is kept in.
func (a *AgentCmd) state() string {
	if a.stateDir == "" {
		return cluster.DefaultDir
	}
	return a.stateDir
}

func (a *AgentCmd) Validate() error {
	if overlay.MaxHost(a.OverlayNet) < 2 {
		return fmt.Errorf("overlay network %s has no room for two nodes", a.OverlayNet)
	}
	for _, p := range a.AllowedIPs {
		if p.Overlaps(a.OverlayNet) {
			return fmt.Errorf("--allowed-ips %s overlaps the overlay network %s", p, a.OverlayNet)
		}
	}

	if a.JoinKey != "" && len(a.Join) == 0 {
		return fmt.Errorf("--join-key needs --join to say which member to enrol with")
	}
	if a.JoinKey != "" && a.Init {
		return fmt.Errorf("--init starts a new cluster; it cannot be combined with --join-key")
	}

	if a.MTU < 576 || a.MTU > 65535 {
		return fmt.Errorf("unsupported MTU %d; must be between 576 and 65535", a.MTU)
	}

	if ka := a.PersistentKeepalive; ka != 0 && (ka < time.Second || ka > 65535*time.Second || ka%time.Second != 0) {
		return fmt.Errorf("unsupported persistent keepalive %s; must be whole seconds between 1s and 65535s", ka)
	}

	return nil
}

// Run wires up cluster, wireguard and the hosts file, joins the cluster and
// runs the agent loop until SIGTERM/SIGINT or ctx is done, reporting to the
// service manager through n.
func (a *AgentCmd) Run(ctx context.Context, n notify.Notifier) error {
	hostname, err := os.Hostname()
	if err != nil {
		return fmt.Errorf("getting hostname: %w", err)
	}
	ctx, cancelSignals := signal.NotifyContext(ctx, syscall.SIGTERM, os.Interrupt)
	defer cancelSignals()
	ctx, stop := context.WithCancel(ctx) // a leave request stops the agent the same way a signal does
	defer stop()

	boot, err := cluster.Load(a.state(), a.Interface, a.Init)
	if err != nil {
		return err
	}
	advertise, err := a.advertiseAddr()
	if err != nil {
		return err
	}

	joinAddrs, err := a.bootstrap(ctx, boot, hostname)
	if err != nil {
		return err
	}

	host, err := boot.Host()
	if err != nil {
		return err
	}
	overlayAddr, ok := overlay.Addr(a.OverlayNet, host)
	if !ok {
		return fmt.Errorf("this node's overlay slot %d does not fit in %s; is --overlay-net the same on every node?", host, a.OverlayNet)
	}
	slog.Debug("assigned overlay address", "addr", overlayAddr, "slot", host)
	wgstate, err := wg.New(wg.Config{
		Interface:           a.Interface,
		Port:                a.WireguardPort,
		OverlayAddr:         overlayAddr,
		MTU:                 a.MTU,
		PersistentKeepalive: a.PersistentKeepalive,
		Userspace:           a.Userspace,
	})
	if err != nil {
		return fmt.Errorf("instantiating wireguard controller: %w", err)
	}
	// what peers learn about us: name, overlay address, wireguard key, routes
	localNode := &overlay.Node{Name: hostname, Meta: overlay.Meta{OverlayAddr: overlayAddr, PubKey: wgstate.PubKey.String(), AllowedIPs: masked(a.AllowedIPs)}}

	cl, err := cluster.New(cluster.Config{
		StateDir: a.state(), StateName: a.Interface, BindAddr: a.BindAddr, AdvertiseAddr: advertise, BindPort: a.ClusterPort,
		OverlayNet: a.OverlayNet, LocalNode: localNode, Boot: boot,
	})
	if err != nil {
		return fmt.Errorf("creating cluster: %w", err)
	}

	leave := &leaving{stop: stop, done: make(chan struct{})}
	ctl, err := control.Listen(socketFor(a.Interface, a.ControlSocket), agentControl{cluster: cl, leaving: leave})
	if err != nil {
		cl.Leave()
		return err
	}
	defer ctl.Close() // answers a leave request once it has been carried out
	defer close(leave.done)

	hostsFile := hostsFor(a.Interface)

	// Keep trying to join until it works or we are told to stop; a node that gives
	// up would need a manual restart, which is worse than a noisy log.
	peerc := cl.Members() // avoid deadlocks by starting before join
	if _, err := backoff.Retry(ctx,
		func() (struct{}, error) { return struct{}{}, cl.Join(joinAddrs) },
		backoff.WithMaxElapsedTime(0),
		backoff.WithNotify(func(err error, dur time.Duration) {
			slog.Error("could not join cluster, retrying", "err", err, "in", dur)
		}),
	); err != nil {
		cl.Leave()
		if ctx.Err() != nil {
			slog.Info("terminating")
			return a.forget(leave)
		}
		return fmt.Errorf("joining cluster: %w", err) // not reached today: the retry gives up only when ctx does
	}

	loopErr := a.loop(ctx, peerc, cl, wgstate, hostsFile, n)
	return errors.Join(loopErr, a.forget(leave))
}

// forget deletes this node's state once a leave has torn everything down, so
// nothing of the cluster it has left is kept.
func (a *AgentCmd) forget(l *leaving) error {
	if !l.requested.Load() {
		return nil
	}
	slog.Info("forgetting the cluster", "interface", a.Interface)
	l.err = cluster.Forget(a.state(), a.Interface) // read by the operator waiting on the control socket
	return l.err
}

// bootstrap settles this node's membership before it joins: a node that is
// already enrolled carries on, --init makes it the root of a new cluster, and
// --join-key enrols it with one of the --join members. It returns the
// addresses to join the gossip ring at.
func (a *AgentCmd) bootstrap(ctx context.Context, boot *cluster.Bootstrap, hostname string) ([]string, error) {
	switch {
	case boot.Enrolled():
		if a.JoinKey != "" {
			slog.Info("already a member of a cluster; ignoring --join-key")
		}
		return a.Join, nil
	case a.Init:
		boot.InitRoot(hostname)
		slog.Info("initialised a new cluster", "root", boot.Root.Short())
		return a.Join, nil
	case a.JoinKey != "":
		w, member, err := a.enrol(ctx, boot.Identity, hostname)
		if err != nil {
			return nil, err
		}
		boot.Enrol(w.Root, w.Records, w.OverlayNet)
		slog.Info("enrolled in cluster", "root", w.Root.Short(), "via", w.GossipAddr, "member", member.Short())
		return []string{w.GossipAddr}, nil
	default:
		return nil, errors.New("this node is not a member of any cluster: use --init to start one, or --join HOST --join-key TOKEN to enrol (get a token with 'cheesecloth invite' on a member)")
	}
}

// masked is the prefixes with their host bits cleared, as routes are written.
func masked(prefixes []netip.Prefix) []netip.Prefix {
	out := make([]netip.Prefix, len(prefixes))
	for i, p := range prefixes {
		out[i] = p.Masked()
	}
	return out
}

// enrol tries each --join member in turn with the join key, returning the
// welcome and the identity of the member that admitted us.
func (a *AgentCmd) enrol(ctx context.Context, id *trust.Identity, name string) (*enrol.Welcome, trust.PublicKey, error) {
	var lastErr error
	for _, addr := range a.enrolAddrs() {
		w, member, err := cluster.Enrol(ctx, addr, a.JoinKey, id, name)
		if err == nil {
			return w, member, nil
		}
		lastErr = fmt.Errorf("enrolling with %s: %w", addr, err)
		slog.Warn("enrolment attempt failed", "member", addr, "err", err)
	}
	return nil, trust.PublicKey{}, lastErr
}

// enrolAddrs are the --join members as ip:port, defaulting to the cluster port.
func (a *AgentCmd) enrolAddrs() []string {
	addrs := make([]string, 0, len(a.Join))
	for _, host := range a.Join {
		if _, _, err := net.SplitHostPort(host); err != nil {
			host = net.JoinHostPort(host, strconv.Itoa(a.ClusterPort))
		}
		addrs = append(addrs, host)
	}
	return addrs
}
