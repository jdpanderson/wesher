package cli

import (
	"github.com/alecthomas/kong"
)

// CLI is the command tree.
type CLI struct {
	Config   kong.ConfigFlag  `help:"configuration file to read instead of ${default_config}" placeholder:"PATH"`
	LogLevel LogLevelFlag     `help:"set the verbosity (debug/info/warn/error)" default:"warn"`
	Version  kong.VersionFlag `help:"display current version and exit"`

	Agent  AgentCmd  `cmd:"" default:"withargs" help:"start the cheesecloth agent (default when no command specified)"`
	Status StatusCmd `cmd:"" help:"show the wireguard interface and its peers"`
	Invite InviteCmd `cmd:"" help:"mint an enrolment token for a new node (talks to the running agent)"`
	Revoke RevokeCmd `cmd:"" help:"revoke a node's membership (talks to the running agent)"`
}

// Parser builds the command-line parser; configPath is the file read when present
// and version is what --version prints.
func Parser(c *CLI, configPath, version string) (*kong.Kong, error) {
	return kong.New(c,
		kong.Name("cheesecloth"),
		kong.Description("mesh overlay network manager. Settings may come from a YAML config file ("+DefaultConfigPath+
			" or --config) keyed by flag name; command-line flags override it."),
		kong.UsageOnError(),
		kong.Vars{"version": version, "default_config": DefaultConfigPath},
		kong.Configuration(configLoader, configPath),
	)
}
