package cli

import (
	"errors"
	"fmt"
	"time"

	"github.com/jdpanderson/cheesecloth/internal/cluster"
	"github.com/jdpanderson/cheesecloth/internal/control"
	"github.com/jdpanderson/cheesecloth/internal/trust"
)

// controlFlags are shared by the commands that talk to a running agent.
type controlFlags struct {
	Interface     string `help:"wireguard interface of the agent to talk to" default:"${default_interface}"`
	ControlSocket string `help:"agent control socket (default /run/cheesecloth/<interface>.sock)"`
}

func (c *controlFlags) socket() string { return socketFor(c.Interface, c.ControlSocket) }

// socketFor is the control socket of the agent for iface, unless one is given explicitly.
func socketFor(iface, explicit string) string {
	if explicit != "" {
		return explicit
	}
	return control.DefaultSocket(iface)
}

// membership is what agentControl needs from a *cluster.Cluster.
type membership interface {
	Invite(ttl time.Duration, uses int) (string, error)
	Revoke(id trust.PublicKey) error
	Trust() *trust.Set
	Identity() trust.PublicKey
}

var _ membership = (*cluster.Cluster)(nil)

// agentControl adapts a Cluster to the control.Handler interface.
type agentControl struct{ cluster membership }

func (a agentControl) Invite(ttl time.Duration, uses int) (string, error) {
	return a.cluster.Invite(ttl, uses)
}

func (a agentControl) Revoke(target string) (string, error) {
	id, err := trust.ParsePublicKey(target)
	if err != nil {
		adm, ok := a.cluster.Trust().ByName(target)
		if !ok {
			return "", fmt.Errorf("no member named %q (give the identity instead if names are ambiguous)", target)
		}
		id = adm.Identity
	}
	if id == a.cluster.Identity() {
		return "", errors.New("refusing to revoke this node itself")
	}
	if err := a.cluster.Revoke(id); err != nil {
		return "", err
	}
	return id.String(), nil
}
