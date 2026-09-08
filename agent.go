package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/costela/wesher/cluster"
	"github.com/costela/wesher/common"
	"github.com/costela/wesher/etchosts"
	"github.com/costela/wesher/wg"
	"github.com/hashicorp/go-sockaddr"
	"github.com/sirupsen/logrus"
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
	if len(a.ClusterKey.bytes) != 0 && len(a.ClusterKey.bytes) != cluster.KeyLen {
		return fmt.Errorf("unsupported cluster key length; expected %d, got %d", cluster.KeyLen, len(a.ClusterKey.bytes))
	}

	if a.OverlayNet.Bits()%8 != 0 {
		return fmt.Errorf("unsupported overlay network size; net mask must be multiple of 8, got %d", a.OverlayNet.Bits())
	}

	if a.BindAddr != "" && a.BindIface != "" {
		return fmt.Errorf("setting both bind address and bind interface is not supported")
	} else if a.BindIface != "" {
		// Compute the actual bind address based on the provided interface
		iface, err := net.InterfaceByName(a.BindIface)
		if err != nil {
			return fmt.Errorf("getting interface by name %s: %w", a.BindIface, err)
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return fmt.Errorf("getting addresses for interface %s: %w", a.BindIface, err)
		}
		if len(addrs) > 0 {
			if addr, ok := addrs[0].(*net.IPNet); ok {
				a.BindAddr = addr.IP.String()
			}
		}
	} else if a.BindAddr == "" && a.BindIface == "" {
		// FIXME: this is a workaround for memberlist refusing to listen on public IPs if BindAddr==0.0.0.0
		detectedBindAddr, err := sockaddr.GetPublicIP()
		if err != nil {
			return err
		}
		// if we cannot find a public IP, let memberlist do its thing
		if detectedBindAddr != "" {
			a.BindAddr = detectedBindAddr
		} else {
			a.BindAddr = "0.0.0.0"
		}
	}

	return nil
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
	cluster, err := cluster.New(a.Interface, a.Init, a.ClusterKey.bytes, a.BindAddr, a.ClusterPort)
	if err != nil {
		return fmt.Errorf("creating cluster: %w", err)
	}
	wgstate, localNode, err := wg.New(a.Interface, a.WireguardPort, a.OverlayNet, cluster.LocalName)
	if err != nil {
		return fmt.Errorf("instantiating wireguard controller: %w", err)
	}

	hostsFile := &etchosts.EtcHosts{
		Banner: "# ! managed automatically by wesher interface " + a.Interface,
		Logger: logrus.StandardLogger(),
	}

	cluster.Update(localNode)

	nodec := cluster.Members() // avoid deadlocks by starting before join
	if err := backoff.RetryNotify(
		func() error { return cluster.Join(a.Join) },
		backoff.NewExponentialBackOff(),
		func(err error, dur time.Duration) {
			logrus.WithError(err).Errorf("could not join cluster, retrying in %s", dur)
		},
	); err != nil {
		return fmt.Errorf("joining cluster: %w", err)
	}

	ctx, cancelSignals := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer cancelSignals()

	return a.loop(ctx, nodec, cluster, wgstate, hostsFile)
}

// loop applies each membership update until ctx is done, then leaves and tears down.
func (a *AgentCmd) loop(ctx context.Context, nodec <-chan []common.Node, cl clusterController, wgstate wgController, hosts hostsWriter) error {
	logrus.Debug("waiting for cluster events")
	for {
		select {
		case rawNodes, ok := <-nodec:
			if !ok {
				return errors.New("cluster membership channel closed")
			}
			a.apply(rawNodes, wgstate, hosts)
		case <-ctx.Done():
			logrus.Info("terminating...")
			cl.Leave()
			if !a.NoEtcHosts {
				if err := hosts.WriteEntries(map[string][]string{}); err != nil {
					logrus.WithError(err).Error("could not remove stale hosts entries")
				}
			}
			if err := wgstate.DownInterface(); err != nil {
				return fmt.Errorf("downing interface: %w", err)
			}
			return nil
		}
	}
}

// apply pushes one membership snapshot to wireguard and /etc/hosts; nodes with undecodable metadata are skipped.
func (a *AgentCmd) apply(rawNodes []common.Node, wgstate wgController, hosts hostsWriter) {
	nodes := make([]common.Node, 0, len(rawNodes))
	hostEntries := make(map[string][]string, len(rawNodes))
	logrus.Info("cluster members:\n")
	for _, node := range rawNodes {
		if err := node.DecodeMeta(); err != nil {
			logrus.Warnf("\t addr: %s, could not decode metadata", node.Addr)
			continue
		}
		logrus.Infof("\taddr: %s, overlay: %s, pubkey: %s", node.Addr, node.OverlayAddr, node.PubKey)
		nodes = append(nodes, node)
		hostEntries[node.OverlayAddr.String()] = []string{node.Name}
	}
	if err := wgstate.SetUpInterface(nodes); err != nil {
		logrus.WithError(err).Error("could not up interface")
		wgstate.DownInterface() // nolint: errcheck // opportunistic
	}
	if !a.NoEtcHosts {
		if err := hosts.WriteEntries(hostEntries); err != nil {
			logrus.WithError(err).Error("could not write hosts entries")
		}
	}
}
