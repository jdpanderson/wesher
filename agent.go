package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cenkalti/backoff/v6"
	"github.com/jdpanderson/wesher/cluster"
	"github.com/jdpanderson/wesher/common"
	"github.com/jdpanderson/wesher/etchosts"
	"github.com/jdpanderson/wesher/wg"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type AgentCmd struct {
	ClusterKey    key          `env:"WESHER_CLUSTER_KEY" help:"shared key for cluster membership; must be 32 bytes base64 encoded; will be generated if not provided"`
	Join          []string     `env:"WESHER_JOIN" help:"comma separated list of hostnames or IP addresses to existing cluster members; if not provided, will attempt resuming any known state or otherwise wait for further members."`
	Init          bool         `env:"WESHER_INIT" help:"whether to explicitly (re)initialize the cluster; any known state from previous runs will be forgotten"`
	BindAddr      netip.Addr   `env:"WESHER_BIND_ADDR" help:"address to bind for cluster membership traffic; 0.0.0.0 or :: binds every interface of that family and advertises one of its addresses. The address family decides whether the cluster runs over IPv4 or IPv6" default:"0.0.0.0"`
	ClusterPort   int          `env:"WESHER_CLUSTER_PORT" help:"port used for membership gossip traffic (both TCP and UDP); must be the same across cluster" default:"7946"`
	WireguardPort int          `env:"WESHER_WIREGUARD_PORT" help:"port used for wireguard traffic (UDP); must be the same across cluster" default:"51820"`
	OverlayNet    netip.Prefix `env:"WESHER_OVERLAY_NET" help:"the network in which to allocate addresses for the overlay mesh network (CIDR format); smaller networks increase the chance of IP collision" default:"10.0.0.0/8"`
	Interface     string       `env:"WESHER_INTERFACE" help:"name of the wireguard interface to create and manage" default:"wgoverlay"`
	MTU           int          `env:"WESHER_MTU" help:"MTU of the wireguard interface" default:"1420"`
	// PersistentKeepalive is a time.Duration so kong accepts "25s"; 0 disables it.
	PersistentKeepalive time.Duration `env:"WESHER_PERSISTENT_KEEPALIVE" help:"interval at which peers send keepalives, to keep NAT mappings open (e.g. 25s); 0 disables" default:"0"`
	NoEtcHosts          bool          `env:"WESHER_NO_ETC_HOSTS" help:"disable writing of entries to /etc/hosts"`
}

func (a *AgentCmd) Validate() error {
	if a.OverlayNet.Bits()%8 != 0 {
		return fmt.Errorf("unsupported overlay network size; net mask must be multiple of 8, got %d", a.OverlayNet.Bits())
	}

	if a.MTU < 576 || a.MTU > 65535 {
		return fmt.Errorf("unsupported MTU %d; must be between 576 and 65535", a.MTU)
	}

	if ka := a.PersistentKeepalive; ka != 0 && (ka < time.Second || ka > 65535*time.Second || ka%time.Second != 0) {
		return fmt.Errorf("unsupported persistent keepalive %s; must be whole seconds between 1s and 65535s", ka)
	}

	return nil
}

// validateNode rejects peer metadata we would not want to install: an overlay
// address outside our overlay net or an unparseable wireguard public key.
func (a *AgentCmd) validateNode(node *common.Node) error {
	if node.Name == "" {
		return errors.New("empty node name")
	}
	if !a.OverlayNet.Contains(node.OverlayAddr) {
		return fmt.Errorf("overlay address %s is outside %s", node.OverlayAddr, a.OverlayNet)
	}
	if _, err := wgtypes.ParseKey(node.PubKey); err != nil {
		return fmt.Errorf("public key: %w", err)
	}
	return nil
}

// advertiseAddr is the address peers use to reach this node for cluster
// membership: the bind address itself, or, for a wildcard, an address of the
// same family on one of this host's interfaces other than the overlay one.
func (a *AgentCmd) advertiseAddr() (netip.Addr, error) {
	if !a.BindAddr.IsUnspecified() {
		return a.BindAddr, nil
	}
	addr, ok := pickAdvertiseAddr(a.BindAddr, upInterfaceAddrs(a.Interface))
	if !ok {
		family := "IPv4"
		if a.BindAddr.Is6() {
			family = "IPv6"
		}
		return netip.Addr{}, fmt.Errorf("no %s address found to advertise for cluster membership; set --bind-addr to a specific address", family)
	}
	return addr, nil
}

// pickAdvertiseAddr chooses, among addrs, an address in the family of wildcard:
// public first, then any global unicast (private ranges included).
func pickAdvertiseAddr(wildcard netip.Addr, addrs []net.Addr) (netip.Addr, bool) {
	inFamily := func(want func(netip.Addr) bool) func(netip.Addr) bool {
		return func(x netip.Addr) bool { return x.Is4() == wildcard.Is4() && want(x) }
	}
	if addr, ok := firstAddr(addrs, inFamily(isPublic)); ok {
		return addr, true
	}
	return firstAddr(addrs, inFamily(netip.Addr.IsGlobalUnicast))
}

// firstAddr returns the first address in addrs accepted by want, with IPv4-mapped addresses unmapped.
func firstAddr(addrs []net.Addr, want func(netip.Addr) bool) (netip.Addr, bool) {
	for _, na := range addrs {
		var ip net.IP
		switch v := na.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		default:
			continue
		}
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			continue
		}
		addr = addr.Unmap()
		if want(addr) {
			return addr, true
		}
	}
	return netip.Addr{}, false
}

// sharedAddressSpace is RFC 6598 carrier-grade NAT space, private for our purposes.
var sharedAddressSpace = netip.MustParsePrefix("100.64.0.0/10")

// isPublic reports whether addr is a globally routable unicast address
// (excludes RFC 1918, RFC 6598 and IPv6 unique local addresses).
func isPublic(addr netip.Addr) bool {
	return addr.IsGlobalUnicast() && !addr.IsPrivate() && !sharedAddressSpace.Contains(addr)
}

// upInterfaceAddrs returns the addresses of all up, non-loopback interfaces
// except the one named skip, in interface order.
func upInterfaceAddrs(skip string) []net.Addr {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var addrs []net.Addr
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || iface.Name == skip {
			continue
		}
		if ifAddrs, err := iface.Addrs(); err == nil {
			addrs = append(addrs, ifAddrs...)
		}
	}
	return addrs
}

// clusterController, wgController and hostsWriter are the parts of the
// cluster, wg and etchosts packages the agent loop drives; they exist so the
// loop can be tested with fakes.
type clusterController interface {
	Members() <-chan []common.Node
	Leave()
}

type wgController interface {
	SetUpInterface([]common.Node) error
	DownInterface() error
}

type hostsWriter interface {
	WriteEntries(map[string][]string) error
}

// Run wires up cluster, wireguard and /etc/hosts, joins the cluster and runs the agent loop until SIGTERM/SIGINT.
func (a *AgentCmd) Run() error {
	hostname, err := os.Hostname()
	if err != nil {
		return fmt.Errorf("getting hostname: %w", err)
	}
	wgstate, localNode, err := wg.New(wg.Config{
		Interface:  a.Interface,
		Port:       a.WireguardPort,
		OverlayNet: a.OverlayNet,
		Name:       hostname,
		MTU:        a.MTU,

		PersistentKeepalive: a.PersistentKeepalive,
	})
	if err != nil {
		return fmt.Errorf("instantiating wireguard controller: %w", err)
	}
	advertise, err := a.advertiseAddr()
	if err != nil {
		return err
	}
	cluster, err := cluster.New(a.Interface, a.Init, a.ClusterKey, a.BindAddr, advertise, a.ClusterPort, localNode)
	if err != nil {
		return fmt.Errorf("creating cluster: %w", err)
	}

	hostsFile := &etchosts.EtcHosts{
		Banner: "# ! managed automatically by wesher interface " + a.Interface,
		Logger: slog.Default(),
	}

	ctx, cancelSignals := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer cancelSignals()

	// Keep trying to join until it works or we are told to stop; a node that gives
	// up would need a manual restart, which is worse than a noisy log.
	nodec := cluster.Members() // avoid deadlocks by starting before join
	if _, err := backoff.Retry(ctx,
		func() (struct{}, error) { return struct{}{}, cluster.Join(a.Join) },
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

// loop applies each membership update until ctx is done, then leaves and tears down.
func (a *AgentCmd) loop(ctx context.Context, nodec <-chan []common.Node, cl clusterController, wgstate wgController, hosts hostsWriter) error {
	slog.Debug("waiting for cluster events")
	for {
		select {
		case rawNodes, ok := <-nodec:
			if !ok {
				return errors.New("cluster membership channel closed")
			}
			a.apply(rawNodes, wgstate, hosts)
		case <-ctx.Done():
			slog.Info("terminating")
			cl.Leave()
			if !a.NoEtcHosts {
				if err := hosts.WriteEntries(map[string][]string{}); err != nil {
					slog.Error("could not remove stale hosts entries", "err", err)
				}
			}
			if err := wgstate.DownInterface(); err != nil {
				return fmt.Errorf("downing interface: %w", err)
			}
			return nil
		}
	}
}

// apply pushes one membership snapshot to wireguard and /etc/hosts; nodes with undecodable or invalid metadata are skipped.
func (a *AgentCmd) apply(rawNodes []common.Node, wgstate wgController, hosts hostsWriter) {
	nodes := make([]common.Node, 0, len(rawNodes))
	hostEntries := make(map[string][]string, len(rawNodes))
	for _, node := range rawNodes {
		if err := node.DecodeMeta(); err != nil {
			slog.Warn("could not decode node metadata, skipping", "addr", node.Addr, "err", err)
			continue
		}
		if err := a.validateNode(&node); err != nil {
			slog.Warn("invalid node metadata, skipping", "name", node.Name, "addr", node.Addr, "err", err)
			continue
		}
		slog.Info("cluster member", "addr", node.Addr, "overlay", node.OverlayAddr, "pubkey", node.PubKey)
		nodes = append(nodes, node)
		hostEntries[node.OverlayAddr.String()] = []string{node.Name}
	}
	if err := wgstate.SetUpInterface(nodes); err != nil {
		slog.Error("could not up interface", "err", err)
		if err := wgstate.DownInterface(); err != nil {
			slog.Warn("could not down interface after failed setup", "err", err)
		}
	}
	if !a.NoEtcHosts {
		if err := hosts.WriteEntries(hostEntries); err != nil {
			slog.Error("could not write hosts entries", "err", err)
		}
	}
}
