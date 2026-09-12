package cli

import (
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"

	"github.com/alecthomas/kong"
	"github.com/jdpanderson/cheesecloth/internal/paths"
	"go.yaml.in/yaml/v3"
)

// Configuration file support: a YAML file whose top-level keys are interface
// names, each holding that interface's settings keyed by flag name, applied as
// kong resolver defaults so command-line flags override them.

// DefaultConfigPath is read when it exists; --config names another file.
var DefaultConfigPath = paths.ConfigFile

// commandLineOnly are flags that must not appear in the config file, with the
// reason the operator is told: --join-key is a one-time secret, --config is
// how the file itself is found.
var commandLineOnly = map[string]string{
	"join-key": "it is a one-time secret; pass it on the command line",
	"config":   "it names the config file itself",
}

// notSettings are flags that are not settings at all, --init among them: it
// tells 'cheesecloth config' to write the file rather than print it. In the
// config file they are unknown keys like any other.
var notSettings = map[string]bool{"help": true, "version": true, "init": true}

// configLoader builds the loader for a config file. One process serves one
// interface, so only that interface's section applies; iface is what
// --interface said on the command line, empty when it said nothing.
func configLoader(iface string) kong.ConfigurationLoader {
	return func(r io.Reader) (kong.Resolver, error) {
		sections, err := parseSections(r)
		if err != nil {
			return nil, err
		}
		name, values, ambiguous := selectSection(sections, iface)
		return &configResolver{sections: sections, iface: name, values: values, ambiguous: ambiguous}, nil
	}
}

// parseSections reads the file as interface name to settings. A top-level
// value that is not a mapping is the shape an operator gets from writing
// settings at the top level, so it is named as such.
func parseSections(r io.Reader) (map[string]map[string]any, error) {
	var file map[string]any
	if err := yaml.NewDecoder(r).Decode(&file); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	sections := map[string]map[string]any{}
	for name, v := range file {
		section, ok := v.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("config: %q is not an interface section; the file is keyed by interface name, with that interface's settings indented under it, as in %q", name, DefaultInterface+":")
		}
		if _, ok := section["interface"]; ok {
			return nil, fmt.Errorf("config: %q cannot be set in section %q: the section name is the interface", "interface", name)
		}
		sections[name] = section
	}
	return sections, nil
}

// selectSection picks the section this command acts under: what --interface
// said, or the only one there is. Several sections with nothing to choose
// between them selects none and is reported as ambiguous, since guessing would
// act on the wrong interface. A named section the file does not have leaves
// every flag at its default.
func selectSection(sections map[string]map[string]any, iface string) (string, map[string]any, bool) {
	switch {
	case iface != "":
		return iface, sections[iface], false
	case len(sections) == 1:
		name := slices.Collect(maps.Keys(sections))[0]
		return name, sections[name], false
	case len(sections) > 1:
		return "", nil, true
	}
	return "", nil, false
}

// configResolver is a kong.Resolver over the selected section of the parsed file.
type configResolver struct {
	sections  map[string]map[string]any
	iface     string         // the interface this command acts as; empty when the file names none
	values    map[string]any // that interface's settings
	ambiguous bool           // several sections and no --interface to choose between them
}

// Validate rejects unknown keys and command-line-only settings, so a typo or a
// misplaced secret is an error rather than silently ignored. Every section is
// checked, not just the selected one: a typo is worth reporting before the
// interface it belongs to is the one being started.
func (c *configResolver) Validate(app *kong.Application) error {
	known := map[string]bool{}
	collectFlags(app.Node, known)
	var bad []string
	for _, name := range slices.Sorted(maps.Keys(c.sections)) {
		for key := range c.sections[name] {
			if reason, only := commandLineOnly[key]; only {
				return fmt.Errorf("config: %q cannot be set in the config file: %s", key, reason)
			}
			if !known[key] || notSettings[key] {
				bad = append(bad, key)
			}
		}
	}
	if len(bad) > 0 {
		slices.Sort(bad)
		return fmt.Errorf("config: unknown setting(s) %s; keys are flag names such as %q", strings.Join(slices.Compact(bad), ", "), "bind-addr")
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

// Resolve implements kong.Resolver. The section name is what --interface
// resolves to, so a single-section file needs no flag to go with it.
// Command-line-only settings are refused here because kong resolves values
// before it validates resolvers.
func (c *configResolver) Resolve(ctx *kong.Context, _ *kong.Path, flag *kong.Flag) (any, error) {
	if flag.Name == "interface" {
		// reported against this flag because supplying it is the way out, and
		// kong names the flag it was resolving in front of the message
		if c.ambiguous && !dumpsEverySection(ctx) {
			return nil, fmt.Errorf("the config file has sections for %s; say which one this command acts on",
				strings.Join(slices.Sorted(maps.Keys(c.sections)), ", "))
		}
		if c.iface == "" {
			return nil, nil
		}
		return c.iface, nil
	}
	v, ok := c.values[flag.Name]
	if !ok {
		return nil, nil
	}
	if reason, only := commandLineOnly[flag.Name]; only {
		return nil, fmt.Errorf("config: %q cannot be set in the config file: %s", flag.Name, reason)
	}
	return v, nil
}

// dumpsEverySection reports whether the command being run is the one that
// prints every section rather than acting on a single interface. It alone
// survives a file with several sections and no --interface to choose between
// them; every other command needs one interface and must say which.
func dumpsEverySection(ctx *kong.Context) bool {
	selected := ctx.Selected()
	return selected != nil && selected.Name == configCmdName
}

// interfaceArg is what --interface says in args, empty when it says nothing.
// The config file cannot be read without it, and kong has not parsed anything
// by the time the file is loaded, so the flag is looked for by hand.
func interfaceArg(args []string) string {
	for i, arg := range args {
		if name, ok := strings.CutPrefix(arg, "--interface="); ok {
			return name
		}
		if arg == "--interface" && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}
