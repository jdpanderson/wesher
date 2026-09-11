package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"

	"github.com/jdpanderson/cheesecloth/internal/sdnotify"
	"github.com/jdpanderson/cheesecloth/overlay"
)

// clusterController, wgController and hostsWriter are the parts of the
// cluster, wg and etchosts packages the agent loop drives; they exist so the
// loop can be tested with fakes.
type clusterController interface {
	Members() <-chan []overlay.Node
	Leave()
}

type wgController interface {
	SetUpInterface([]overlay.Node) error
	DownInterface() error
}

type hostsWriter interface {
	WriteEntries(map[string][]string) error
}

// loop applies each membership update until ctx is done, then leaves and
// tears down. systemd is told the service is ready once the interface has been
// configured from the first snapshot, and kept posted on the peer count.
func (a *AgentCmd) loop(ctx context.Context, nodec <-chan []overlay.Node, cl clusterController, wgstate wgController, hosts hostsWriter) error {
	slog.Debug("waiting for cluster events")
	notify := sdnotify.Ready
	for {
		select {
		case rawNodes, ok := <-nodec:
			if !ok {
				return errors.New("cluster membership channel closed")
			}
			peers := a.apply(rawNodes, wgstate, hosts)
			if err := notify(fmt.Sprintf("%d peers", peers)); err != nil {
				slog.Warn("could not notify systemd", "err", err)
			}
			notify = sdnotify.Status
		case <-ctx.Done():
			slog.Info("terminating")
			if err := sdnotify.Stopping(); err != nil {
				slog.Warn("could not notify systemd", "err", err)
			}
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

// apply pushes one membership snapshot, already verified by the cluster, to
// wireguard and /etc/hosts and returns the number of peers installed. A
// network advertised by more than one node goes to the first by name, so
// every snapshot resolves the same way. The nodes' route slices are shared
// with the cluster, which persists them, so they are filtered into new
// slices rather than in place.
func (a *AgentCmd) apply(nodes []overlay.Node, wgstate wgController, hosts hostsWriter) int {
	hostEntries := make(map[string][]string, len(nodes))
	routedBy := map[netip.Prefix]string{}
	slices.SortFunc(nodes, func(x, y overlay.Node) int { return strings.Compare(x.Name, y.Name) })
	for i := range nodes {
		node := &nodes[i]
		var routes []netip.Prefix
		for _, p := range node.AllowedIPs {
			switch by, taken := routedBy[p]; {
			case p.Overlaps(a.OverlayNet):
				slog.Warn("ignoring advertised network inside the overlay net", "name", node.Name, "net", p)
			case taken:
				slog.Warn("network advertised by two nodes, keeping the first", "net", p, "kept", by, "ignored", node.Name)
			default:
				routedBy[p] = node.Name
				routes = append(routes, p)
			}
		}
		node.AllowedIPs = routes
		slog.Info("cluster member", "addr", node.Addr, "overlay", node.OverlayAddr, "pubkey", node.PubKey, "routes", node.AllowedIPs)
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
	return len(nodes)
}
