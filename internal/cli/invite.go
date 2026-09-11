package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/jdpanderson/cheesecloth/internal/control"
)

// InviteCmd mints an enrolment token on the running agent.
type InviteCmd struct {
	controlFlags
	TTL  time.Duration `help:"how long the token stays valid" default:"10m"`
	Uses int           `help:"how many nodes may enrol with the token" default:"1"`
}

func (c *InviteCmd) Run() error {
	resp, err := control.Call(c.socket(), control.Request{Op: control.OpInvite, TTL: c.TTL.String(), Uses: c.Uses})
	if err != nil {
		return err
	}
	fmt.Println(resp.Token)
	fmt.Fprintf(os.Stderr, "valid for %s, %d use(s). On the new node:\n  cheesecloth --join <this host> --join-key %s\n", c.TTL, c.Uses, resp.Token)
	return nil
}
