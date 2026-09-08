package cli

import (
	"errors"
	"fmt"
	"time"

	"github.com/jdpanderson/cheesecloth/cluster"
	"github.com/jdpanderson/cheesecloth/control"
	"github.com/jdpanderson/cheesecloth/trust"
)

// controlFlags are shared by the commands that talk to a running agent.
type controlFlags struct {
	Interface     string `help:"wireguard interface of the agent to talk to" default:"wgoverlay"`
	ControlSocket string `help:"agent control socket (default /run/cheesecloth/<interface>.sock)"`
}

func (c *controlFlags) socket() string {
	if c.ControlSocket != "" {
		return c.ControlSocket
	}
	return control.DefaultSocket(c.Interface)
}

// agentControl adapts a Cluster to the control.Handler interface.
type agentControl struct{ cluster *cluster.Cluster }

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
