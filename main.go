package main // import "github.com/jdpanderson/cheesecloth"

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/alecthomas/kong"
)

var version = "dev"

type cli struct {
	Config   kong.ConfigFlag  `help:"configuration file to read instead of ${default_config}" placeholder:"PATH"`
	LogLevel LogLevelFlag     `help:"set the verbosity (debug/info/warn/error)" default:"warn"`
	Version  kong.VersionFlag `help:"display current version and exit"`

	Agent  AgentCmd  `cmd:"" default:"withargs" help:"start the cheesecloth agent (default when no command specified)"`
	Status StatusCmd `cmd:"" help:"show the wireguard interface and its peers"`
	Invite InviteCmd `cmd:"" help:"mint an enrolment token for a new node (talks to the running agent)"`
	Revoke RevokeCmd `cmd:"" help:"revoke a node's membership (talks to the running agent)"`
}

func main() {
	cli := &cli{}
	k, err := parser(cli, DefaultConfigPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cheesecloth:", err)
		os.Exit(1)
	}
	ktx, err := k.Parse(os.Args[1:])
	k.FatalIfErrorf(err)
	k.FatalIfErrorf(ktx.Run())
}

type LogLevelFlag string

// AfterApply installs the default slog logger at the requested level.
func (l LogLevelFlag) AfterApply() error {
	var level slog.Level
	if err := level.UnmarshalText([]byte(l)); err != nil {
		return fmt.Errorf("could not parse log level: %w", err)
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))
	return nil
}
