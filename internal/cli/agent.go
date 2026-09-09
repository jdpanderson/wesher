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
	"github.com/jdpanderson/cheesecloth/cluster"
	"github.com/jdpanderson/cheesecloth/common"
	"github.com/jdpanderson/cheesecloth/control"
	"github.com/jdpanderson/cheesecloth/enroll"
	"github.com/jdpanderson/cheesecloth/etchosts"
	"github.com/jdpanderson/cheesecloth/trust"
	"github.com/jdpanderson/cheesecloth/wg"
)

// AgentCmd is the long-running daemon: it joins the cluster and keeps the
// wireguard interface and /etc/hosts in step with the membership.
type AgentCmd struct {
	Join          []string     `help:"comma separated list of hostnames or IP addresses of existing cluster members; if not provided, will attempt resuming any known state or otherwise wait for further members."`
	JoinKey       string       `help:"invitation token from 'cheesecloth invite' on a member, needed only the first time this node joins"`
	Init          bool         `help:"start a new cluster with this node as its root; any known state from previous runs will be forgotten"`
	BindAddr      netip.Addr   `help:"address to bind for cluster membership traffic; 0.0.0.0 or :: binds every interface of that family and advertises one of its addresses. The address family decides whether the cluster runs over IPv4 or IPv6" default:"0.0.0.0"`
	ClusterPort   int          `help:"port used for membership gossip traffic (both TCP and UDP); must be the same across cluster" default:"7946"`
	WireguardPort int          `help:"port used for wireguard traffic (UDP); must be the same across cluster" default:"51820"`
	OverlayNet    netip.Prefix `help:"the network in which to allocate addresses for the overlay mesh network (CIDR format); must be the same across cluster" default:"10.0.0.0/8"`
	Interface     string       `help:"name of the wireguard interface to create and manage" default:"wgoverlay"`
	MTU           int          `help:"MTU of the wireguard interface" default:"1420"`
	// PersistentKeepalive is a time.Duration so kong accepts "25s"; 0 disables it.
	PersistentKeepalive time.Duration `help:"interval at which peers send keepalives, to keep NAT mappings open (e.g. 25s); 0 disables" default:"0"`
	NoEtcHosts          bool          `help:"disable writing of entries to /etc/hosts"`
	ControlSocket       string        `help:"unix socket for 'cheesecloth invite' and 'cheesecloth revoke' (default /run/cheesecloth/<interface>.sock)"`
}

func (a *AgentCmd) Validate() error {
	if common.MaxHost(a.OverlayNet) < 2 {
		return fmt.Errorf("overlay network %s has no room for two nodes", a.OverlayNet)
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

// Run wires up cluster, wireguard and /etc/hosts, joins the cluster and runs the agent loop until SIGTERM/SIGINT.
func (a *AgentCmd) Run() error {
	hostname, err := os.Hostname()
	if err != nil {
		return fmt.Errorf("getting hostname: %w", err)
	}
	ctx, cancelSignals := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer cancelSignals()

	boot, err := cluster.Load(a.Interface, a.Init)
	if err != nil {
		return err
	}
	advertise, err := a.advertiseAddr()
	if err != nil {
		return err
	}

	known := map[string]trust.PublicKey{}
	joinAddrs := a.Join
	switch {
	case boot.Enrolled():
		if a.JoinKey != "" {
			slog.Info("already a member of a cluster; ignoring --join-key")
		}
	case a.Init:
		boot.InitRoot(hostname, nil)
		slog.Info("initialised a new cluster", "root", boot.Root.Short())
	case a.JoinKey != "":
		w, memberID, enrolErr := a.enrol(ctx, boot.Identity, hostname)
		if enrolErr != nil {
			return enrolErr
		}
		boot.Enrol(w.Root, w.Records)
		known[w.GossipAddr] = memberID
		joinAddrs = []string{w.GossipAddr}
		slog.Info("enrolled in cluster", "root", w.Root.Short(), "via", w.GossipAddr)
	default:
		return errors.New("this node is not a member of any cluster: use --init to start one, or --join HOST --join-key TOKEN to enrol (get a token with 'cheesecloth invite' on a member)")
	}

	host, err := boot.Host()
	if err != nil {
		return err
	}
	overlayAddr, ok := common.OverlayAddr(a.OverlayNet, host)
	if !ok {
		return fmt.Errorf("this node's overlay slot %d does not fit in %s; is --overlay-net the same on every node?", host, a.OverlayNet)
	}
	slog.Debug("assigned overlay address", "addr", overlayAddr, "slot", host)
	wgstate, localNode, err := wg.New(wg.Config{
		Interface:   a.Interface,
		Port:        a.WireguardPort,
		OverlayNet:  a.OverlayNet,
		OverlayAddr: overlayAddr,
		Name:        hostname,
		MTU:         a.MTU,

		PersistentKeepalive: a.PersistentKeepalive,
	})
	if err != nil {
		return fmt.Errorf("instantiating wireguard controller: %w", err)
	}

	cluster, err := cluster.New(cluster.Config{
		Name: a.Interface, BindAddr: a.BindAddr, AdvertiseAddr: advertise, BindPort: a.ClusterPort, EnrolPort: a.WireguardPort,
		OverlayNet: a.OverlayNet, LocalNode: localNode, Identity: boot.Identity, Root: boot.Root, Records: boot.Records,
		Peers: boot.Peers, Known: known,
	})
	if err != nil {
		return fmt.Errorf("creating cluster: %w", err)
	}

	socket := a.ControlSocket
	if socket == "" {
		socket = control.DefaultSocket(a.Interface)
	}
	ctl, err := control.Listen(socket, agentControl{cluster})
	if err != nil {
		cluster.Leave()
		return err
	}
	defer ctl.Close()

	hostsFile := &etchosts.EtcHosts{
		Banner: "# ! managed automatically by cheesecloth interface " + a.Interface,
		Logger: slog.Default(),
	}

	// Keep trying to join until it works or we are told to stop; a node that gives
	// up would need a manual restart, which is worse than a noisy log.
	nodec := cluster.Members() // avoid deadlocks by starting before join
	if _, err := backoff.Retry(ctx,
		func() (struct{}, error) { return struct{}{}, cluster.Join(joinAddrs) },
		backoff.WithMaxElapsedTime(0),
		backoff.WithNotify(func(err error, dur time.Duration) {
			slog.Error("could not join cluster, retrying", "err", err, "in", dur)
		}),
	); err != nil {
		if ctx.Err() != nil {
			slog.Info("terminating")
			cluster.Leave()
			return nil
		}
		return fmt.Errorf("joining cluster: %w", err)
	}

	return a.loop(ctx, nodec, cluster, wgstate, hostsFile)
}

// enrol tries each --join host's enrolment port with the join key.
func (a *AgentCmd) enrol(ctx context.Context, id *trust.Identity, name string) (*enroll.Welcome, trust.PublicKey, error) {
	var lastErr error
	for _, host := range a.Join {
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h // --join may carry the gossip port; enrolment uses the wireguard port
		}
		addr := net.JoinHostPort(host, strconv.Itoa(a.WireguardPort))
		w, memberID, err := enroll.Join(ctx, addr, a.JoinKey, id, name)
		if err == nil {
			return w, memberID, nil
		}
		lastErr = fmt.Errorf("enrolling with %s: %w", addr, err)
		slog.Warn("enrolment attempt failed", "member", addr, "err", err)
	}
	return nil, trust.PublicKey{}, lastErr
}
