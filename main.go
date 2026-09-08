package main // import "github.com/costela/wesher"

import (
	"github.com/alecthomas/kong"
	"github.com/sirupsen/logrus"
)

var version = "dev"

type cli struct {
	LogLevel LogLevelFlag     `env:"WESHER_LOG_LEVEL" help:"set the verbosity (debug/info/warn/error)" default:"warn"`
	Version  kong.VersionFlag `help:"display current version and exit"`

	Agent AgentCmd `cmd:"" default:"withargs" help:"start the wesher agent (default when no command specified)"`
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

func (l LogLevelFlag) AfterApply() error {
	logLevel, err := logrus.ParseLevel(string(l))
	if err != nil {
		logrus.WithError(err).Fatal("could not parse loglevel")
	}
	logrus.SetLevel(logLevel)

	return nil
}
