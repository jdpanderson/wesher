package main // import "github.com/costela/wesher"

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/alecthomas/kong"
)

var version = "dev"

type cli struct {
	LogLevel LogLevelFlag     `env:"WESHER_LOG_LEVEL" help:"set the verbosity (debug/info/warn/error)" default:"warn"`
	Version  kong.VersionFlag `help:"display current version and exit"`

	Agent   AgentCmd   `cmd:"" default:"withargs" help:"start the wesher agent (default when no command specified)"`
	ShowKey ShowKeyCmd `cmd:"" name:"showkey" help:"print the cluster key persisted for an interface"`
}

func main() {
	cli := &cli{}
	ktx := kong.Parse(cli,
		kong.Name("wesher"),
		kong.Description("mesh overlay network manager"),
		kong.UsageOnError(),
		kong.Vars{"version": version},
	)

	err := ktx.Run(cli)
	ktx.FatalIfErrorf(err)
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
