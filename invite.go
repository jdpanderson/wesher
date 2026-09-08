package main

import (
	"errors"
	"fmt"
	"os"
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

// InviteCmd mints an enrolment token on the running agent.
type InviteCmd struct {
	controlFlags
	TTL  time.Duration `help:"how long the token stays valid" default:"10m"`
	Uses int           `help:"how many nodes may enrol with the token" default:"1"`
}

func (c *InviteCmd) Run() error {
	resp, err := control.Call(c.socket(), control.Request{Op: "invite", TTL: c.TTL.String(), Uses: c.Uses})
	if err != nil {
		return err
	}
	fmt.Println(resp.Token)
	fmt.Fprintf(os.Stderr, "valid for %s, %d use(s). On the new node:\n  cheesecloth --join <this host> --join-key %s\n", c.TTL, c.Uses, resp.Token)
	return nil
}

// RevokeCmd removes a node from the membership.
type RevokeCmd struct {
	controlFlags
	Target string `arg:"" help:"node name or identity to revoke"`
}

func (c *RevokeCmd) Run() error {
	resp, err := control.Call(c.socket(), control.Request{Op: "revoke", Target: c.Target})
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "revoked %s (%s)\n", c.Target, resp.Identity)
	return nil
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
