package cli

import (
	"bytes"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"

	"github.com/jdpanderson/cheesecloth/internal/cluster"
	"go.yaml.in/yaml/v3"
)

// configCmdName is the command that prints settings rather than acting on a
// single interface, which is why it alone survives an ambiguous config file.
const configCmdName = "config"

// ConfigCmd reports the settings an interface runs with, as config file
// sections. Printed, they can be redirected somewhere; with --init they are
// written to the config file, which is how a node is set up before its agent
// is started for the first time.
type ConfigCmd struct {
	settings `embed:""`
	Init     bool `help:"write the settings to the config file as a new section for this interface, instead of printing them"`
}

func (c *ConfigCmd) Validate() error { return c.check() }

// section is a config file section, in the order the settings are written.
// Everything is omitted when empty, so only what differs from the defaults is
// written and the file stays as short as what the operator has to maintain.
type section struct {
	Join                []string `yaml:"join,omitempty"`
	BindAddr            string   `yaml:"bind-addr,omitempty"`
	ClusterPort         int      `yaml:"cluster-port,omitempty"`
	WireguardPort       int      `yaml:"wireguard-port,omitempty"`
	OverlayNet          string   `yaml:"overlay-net,omitempty"`
	AllowedIPs          []string `yaml:"allowed-ips,omitempty"`
	MTU                 int      `yaml:"mtu,omitempty"`
	PersistentKeepalive string   `yaml:"persistent-keepalive,omitempty"`
	NoEtcHosts          bool     `yaml:"no-etc-hosts,omitempty"`
	Userspace           bool     `yaml:"userspace,omitempty"`
	ControlSocket       string   `yaml:"control-socket,omitempty"`
	LogLevel            string   `yaml:"log-level,omitempty"`
}

func (c *ConfigCmd) Run(cli *CLI) error {
	if c.Init {
		rendered, err := c.render(cli.LogLevel)
		if err != nil {
			return err
		}
		return c.write(cli.ConfigPath(), rendered)
	}
	rendered, err := c.dump(cli)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(rendered)
	return err
}

// dump is what the command prints. Told which interface to act on, it reports
// that one's settings as the agent would settle them, the command line
// included. Told nothing, it reports every section the file holds, as the file
// holds them, since there is no one section for a flag on this command line to
// belong to.
func (c *ConfigCmd) dump(cli *CLI) ([]byte, error) {
	if cli.ifaceArg != "" {
		return c.render(cli.LogLevel)
	}
	sections, err := readSections(cli.ConfigPath())
	if err != nil {
		return nil, err
	}
	if len(sections) == 0 {
		return c.render(cli.LogLevel)
	}
	return c.renderAll(sections)
}

// renderAll is every section of the config file, each with the overlay network
// the cluster told that interface where the file does not say it itself.
func (c *ConfigCmd) renderAll(sections map[string]map[string]any) ([]byte, error) {
	out := map[string]section{}
	for name, values := range sections {
		s, err := sectionOf(values)
		if err != nil {
			return nil, fmt.Errorf("reading the %s section: %w", name, err)
		}
		if s.OverlayNet == "" {
			if net, ok := cluster.KnownOverlayNet(c.state(), name); ok {
				s.OverlayNet = net.String()
			}
		}
		out[name] = s
	}
	return encode(out)
}

// sectionOf types a section as the file holds it, so that what is printed
// keeps the order and shape of what is written.
func sectionOf(values map[string]any) (section, error) {
	var s section
	raw, err := yaml.Marshal(values)
	if err != nil {
		return s, err
	}
	return s, yaml.Unmarshal(raw, &s)
}

// readSections is the config file's sections, none when it is not there.
func readSections(path string) (map[string]map[string]any, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	return parseSections(bytes.NewReader(content))
}

// render is this interface's section as it goes into a config file.
func (c *ConfigCmd) render(logLevel LogLevelFlag) ([]byte, error) {
	def, err := defaultSettings()
	if err != nil {
		return nil, err
	}
	s := section{Join: c.Join}
	if c.BindAddr != def.BindAddr {
		s.BindAddr = c.BindAddr.String()
	}
	if c.ClusterPort != def.ClusterPort {
		s.ClusterPort = c.ClusterPort
	}
	if c.WireguardPort != def.WireguardPort {
		s.WireguardPort = c.WireguardPort
	}
	if net := c.overlayNet(); net.IsValid() {
		s.OverlayNet = net.String()
	}
	for _, p := range c.AllowedIPs {
		s.AllowedIPs = append(s.AllowedIPs, p.String())
	}
	if c.MTU != def.MTU {
		s.MTU = c.MTU
	}
	if c.PersistentKeepalive != def.PersistentKeepalive {
		s.PersistentKeepalive = c.PersistentKeepalive.String()
	}
	s.NoEtcHosts, s.Userspace, s.ControlSocket = c.NoEtcHosts, c.Userspace, c.ControlSocket
	if string(logLevel) != DefaultLogLevel {
		s.LogLevel = string(logLevel)
	}

	return encode(map[string]section{c.Interface: s})
}

// encode writes the sections as the config file spells them.
func encode(sections map[string]section) ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(sections); err != nil {
		return nil, fmt.Errorf("rendering the settings: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("rendering the settings: %w", err)
	}
	return buf.Bytes(), nil
}

// overlayNet is the network this node allocates addresses in, as the agent
// settles it: what the command line or the config file says, then what the
// cluster told this node. Neither means the default applies and there is
// nothing worth writing down.
func (c *ConfigCmd) overlayNet() netip.Prefix {
	if c.OverlayNet.IsValid() {
		return c.OverlayNet.Masked()
	}
	net, _ := cluster.KnownOverlayNet(c.state(), c.Interface)
	return net
}

// write appends the section to the config file, creating it if it is not
// there. The file is appended to rather than rewritten so that the comments
// of the one the package ships survive.
func (c *ConfigCmd) write(path string, rendered []byte) error {
	existing, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("reading %s: %w", path, err)
	}
	sections, err := parseSections(bytes.NewReader(existing))
	if err != nil {
		return err
	}
	if _, taken := sections[c.Interface]; taken {
		return fmt.Errorf("%s already has a section for %q; edit it, or run 'cheesecloth config' to print the settings and redirect them yourself", path, c.Interface)
	}

	if err = os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	if err := appendSection(f, existing, rendered); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	fmt.Fprintf(os.Stderr, "wrote the %s section to %s\n", c.Interface, path)
	return f.Close()
}

// appendSection writes the section after what the file already holds, with a
// blank line between the two so an existing file stays readable.
func appendSection(w io.Writer, existing, rendered []byte) error {
	var lead string
	if n := len(existing); n > 0 {
		lead = "\n"
		if existing[n-1] != '\n' {
			lead = "\n\n"
		}
	}
	_, err := io.WriteString(w, lead+string(rendered))
	return err
}
