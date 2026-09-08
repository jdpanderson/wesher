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
	"github.com/costela/wesher/cluster"
	"github.com/costela/wesher/common"
	"github.com/costela/wesher/etchosts"
	"github.com/costela/wesher/wg"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type AgentCmd struct {
	ClusterKey    key          `env:"WESHER_CLUSTER_KEY" help:"shared key for cluster membership; must be 32 bytes base64 encoded; will be generated if not provided"`
	Join          []string     `env:"WESHER_JOIN" help:"comma separated list of hostnames or IP addresses to existing cluster members; if not provided, will attempt resuming any known state or otherwise wait for further members."`
	Init          bool         `env:"WESHER_INIT" help:"whether to explicitly (re)initialize the cluster; any known state from previous runs will be forgotten"`
	BindAddr      string       `env:"WESHER_BIND_ADDR" help:"IP address to bind to for cluster membership traffic (cannot be used with --bind-iface)"`
	BindIface     string       `env:"WESHER_BIND_IFACE" help:"Interface to bind to for cluster membership traffic (cannot be used with --bind-addr)"`
	ClusterPort   int          `env:"WESHER_CLUSTER_PORT" help:"port used for membership gossip traffic (both TCP and UDP); must be the same across cluster" default:"7946"`
	WireguardPort int          `env:"WESHER_WIREGUARD_PORT" help:"port used for wireguard traffic (UDP); must be the same across cluster" default:"51820"`
	OverlayNet    netip.Prefix `env:"WESHER_OVERLAY_NET" help:"the network in which to allocate addresses for the overlay mesh network (CIDR format); smaller networks increase the chance of IP collision" default:"10.0.0.0/8"`
	Interface     string       `env:"WESHER_INTERFACE" help:"name of the wireguard interface to create and manage" default:"wgoverlay"`
	NoEtcHosts    bool         `env:"WESHER_NO_ETC_HOSTS" help:"disable writing of entries to /etc/hosts"`
}

func (a *AgentCmd) Validate() error {
	if a.OverlayNet.Bits()%8 != 0 {
		return fmt.Errorf("unsupported overlay network size; net mask must be multiple of 8, got %d", a.OverlayNet.Bits())
	}

	switch {
	case a.BindAddr != "" && a.BindIface != "":
		return fmt.Errorf("setting both bind address and bind interface is not supported")
	case a.BindIface != "":
		iface, err := net.InterfaceByName(a.BindIface)
		if err != nil {
			return fmt.Errorf("getting interface by name %s: %w", a.BindIface, err)
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return fmt.Errorf("getting addresses for interface %s: %w", a.BindIface, err)
		}
		addr, ok := firstIPv4(addrs, netip.Addr.IsGlobalUnicast)
		if !ok {
			addr, ok = firstIPv4(addrs, func(netip.Addr) bool { return true })
		}
		if !ok {
			return fmt.Errorf("no IPv4 address on interface %s", a.BindIface)
		}
		a.BindAddr = addr.String()
	case a.BindAddr == "":
		// memberlist refuses to bind 0.0.0.0 unless it can find a private IP to advertise,
		// so prefer a public address; otherwise let memberlist pick a private one.
		addr, ok := firstIPv4(upInterfaceAddrs(), isPublic)
		if !ok {
			addr = netip.IPv4Unspecified()
		}
		a.BindAddr = addr.String()
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

// firstIPv4 returns the first IPv4 address in addrs accepted by want.
func firstIPv4(addrs []net.Addr, want func(netip.Addr) bool) (netip.Addr, bool) {
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
		if addr.Is4() && want(addr) {
			return addr, true
		}
	}
	return netip.Addr{}, false
}

// sharedAddressSpace is RFC 6598 carrier-grade NAT space, private for our purposes.
var sharedAddressSpace = netip.MustParsePrefix("100.64.0.0/10")

// isPublic reports whether addr is a globally routable unicast address.
func isPublic(addr netip.Addr) bool {
	return addr.IsGlobalUnicast() && !addr.IsPrivate() && !sharedAddressSpace.Contains(addr)
}

// upInterfaceAddrs returns the addresses of all up, non-loopback interfaces, in interface order.
func upInterfaceAddrs() []net.Addr {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var addrs []net.Addr
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
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
func (a *AgentCmd) Run(cli *cli) error {
	hostname, err := os.Hostname()
	if err != nil {
		return fmt.Errorf("getting hostname: %w", err)
	}
	wgstate, localNode, err := wg.New(a.Interface, a.WireguardPort, a.OverlayNet, hostname)
	if err != nil {
		return fmt.Errorf("instantiating wireguard controller: %w", err)
	}
	cluster, err := cluster.New(a.Interface, a.Init, a.ClusterKey, a.BindAddr, a.ClusterPort, localNode)
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
		wgstate.DownInterface() // nolint: errcheck // opportunistic
	}
	if !a.NoEtcHosts {
		if err := hosts.WriteEntries(hostEntries); err != nil {
			slog.Error("could not write hosts entries", "err", err)
		}
	}
}
