package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/jdpanderson/cheesecloth/common"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

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
