package cli

import (
	"net/netip"
	"os"
	"time"

	"github.com/jdpanderson/cheesecloth/cluster"
	"github.com/jdpanderson/cheesecloth/trust"
	"github.com/jdpanderson/cheesecloth/wg"
)

// StatusCmd shows the live wireguard state of a cheesecloth interface, naming peers
// from the persisted cluster state. Needs the same privileges as the agent.
type StatusCmd struct {
	Interface string `help:"wireguard interface to report on" default:"${default_interface}"`
	JSON      bool   `help:"print the report as JSON"`
}

func (c *StatusCmd) Run() error {
	report, err := wg.Status(c.Interface)
	if err != nil {
		return err
	}
	names := make(map[string]peerInfo) // wireguard public key -> node
	for _, n := range cluster.KnownNodes(c.Interface) {
		id := trust.PublicKey(n.Identity)
		names[n.PubKey] = peerInfo{Name: n.Name, Identity: &id, Overlay: n.OverlayAddr}
	}
	local, _ := cluster.LocalIdentity(c.Interface)
	if c.JSON {
		return renderStatusJSON(os.Stdout, report, local, names)
	}
	return renderStatus(os.Stdout, report, local, names, time.Now())
}

// peerInfo is what the cluster state knows about a wireguard peer.
type peerInfo struct {
	Name     string           `json:"name,omitempty"`
	Identity *trust.PublicKey `json:"identity,omitempty"`
	Overlay  netip.Addr       `json:"overlay,omitzero"`
}
