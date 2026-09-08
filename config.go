package main

import (
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/alecthomas/kong"
	"go.yaml.in/yaml/v3"
)

// DefaultConfigPath is read when it exists; --config names another file.
const DefaultConfigPath = "/etc/cheesecloth/config.yaml"

// commandLineOnly are flags that must not appear in the config file: --join-key
// is a one-time secret, --init is a one-time destructive action, --config is
// how the file itself is found.
var commandLineOnly = map[string]string{
	"join-key": "it is a one-time secret; pass it on the command line",
	"init":     "it starts a new cluster and forgets state; pass it on the command line once",
	"config":   "it names the config file itself",
	"help":     "",
	"version":  "",
}

// configLoader parses a YAML config file whose keys are flag names, e.g.
// "bind-addr: ::". Values apply to every command that has the flag, and an
// explicit command-line flag always wins.
func configLoader(r io.Reader) (kong.Resolver, error) {
	var values map[string]any
	if err := yaml.NewDecoder(r).Decode(&values); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	if values == nil {
		values = map[string]any{}
	}
	return &configResolver{values: values}, nil
}

// configResolver is a kong.Resolver over the parsed file.
type configResolver struct {
	values map[string]any
}

// Validate rejects unknown keys and command-line-only settings, so a typo or a
// misplaced secret is an error rather than silently ignored.
func (c *configResolver) Validate(app *kong.Application) error {
	known := map[string]bool{}
	collectFlags(app.Node, known)
	var bad []string
	for key := range c.values {
		switch reason, only := commandLineOnly[key]; {
		case only && reason != "":
			return fmt.Errorf("config: %q cannot be set in the config file: %s", key, reason)
		case only, !known[key]:
			bad = append(bad, key)
		}
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		return fmt.Errorf("config: unknown setting(s) %s; keys are flag names such as %q", strings.Join(bad, ", "), "bind-addr")
	}
	return nil
}

func collectFlags(n *kong.Node, into map[string]bool) {
	for _, f := range n.Flags {
		into[f.Name] = true
	}
	for _, child := range n.Children {
		collectFlags(child, into)
	}
}

// Resolve implements kong.Resolver. Command-line-only settings are refused
// here because kong resolves values before it validates resolvers.
func (c *configResolver) Resolve(_ *kong.Context, _ *kong.Path, flag *kong.Flag) (any, error) {
	v, ok := c.values[flag.Name]
	if !ok {
		return nil, nil
	}
	if reason, only := commandLineOnly[flag.Name]; only {
		return nil, fmt.Errorf("config: %q cannot be set in the config file: %s", flag.Name, reason)
	}
	return v, nil
}

// parser builds the command-line parser; configPath is the file read when present.
func parser(cli *cli, configPath string) (*kong.Kong, error) {
	return kong.New(cli,
		kong.Name("cheesecloth"),
		kong.Description("mesh overlay network manager. Settings may come from a YAML config file ("+DefaultConfigPath+
			" or --config) keyed by flag name; command-line flags override it."),
		kong.UsageOnError(),
		kong.Vars{"version": version, "default_config": DefaultConfigPath},
		kong.Configuration(configLoader, configPath),
	)
}
