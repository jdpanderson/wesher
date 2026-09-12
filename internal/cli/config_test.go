package cli

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	return path
}

// parse runs the real parser with configPath as the default config file.
func parse(t *testing.T, configPath string, args ...string) (*CLI, error) {
	t.Helper()
	c := &CLI{}
	k, err := Parser(c, configPath, "test", args)
	if err != nil { // a broken default config file is reported at construction
		return c, err
	}
	_, err = k.Parse(args)
	return c, err
}

func Test_config_appliesToAgentAndOtherCommands(t *testing.T) {
	path := writeConfig(t, `
wg7:
  bind-addr: "::"
  cluster-port: 17946
  wireguard-port: 51821
  overlay-net: fd00:10::/64
  mtu: 1380
  persistent-keepalive: 25s
  no-etc-hosts: true
  log-level: debug
  join:
    - a.example.net
    - b.example.net
`)
	c, err := parse(t, path, "agent")
	require.NoError(t, err)
	assert.Equal(t, netip.IPv6Unspecified(), c.Agent.BindAddr)
	assert.Equal(t, 17946, c.Agent.ClusterPort)
	assert.Equal(t, 51821, c.Agent.WireguardPort)
	assert.Equal(t, "fd00:10::/64", c.Agent.OverlayNet.String())
	assert.Equal(t, "wg7", c.Agent.Interface, "the section name is the interface")
	assert.Equal(t, 1380, c.Agent.MTU)
	assert.Equal(t, 25*time.Second, c.Agent.PersistentKeepalive)
	assert.True(t, c.Agent.NoEtcHosts)
	assert.Equal(t, LogLevelFlag("debug"), c.LogLevel)
	assert.Equal(t, []string{"a.example.net", "b.example.net"}, c.Agent.Join)

	// the same file tells the operator commands which agent to talk to
	c, err = parse(t, path, "status")
	require.NoError(t, err)
	assert.Equal(t, "wg7", c.Status.Interface)
	c, err = parse(t, path, "invite")
	require.NoError(t, err)
	assert.Equal(t, "wg7", c.Invite.Interface)
}

func Test_config_commandLineOverrides(t *testing.T) {
	path := writeConfig(t, "wg7:\n  mtu: 1380\n  log-level: debug\n")
	c, err := parse(t, path, "--log-level", "error", "agent", "--mtu", "1300")
	require.NoError(t, err)
	assert.Equal(t, 1300, c.Agent.MTU, "flag wins")
	assert.Equal(t, "wg7", c.Agent.Interface, "unset flag takes the config value")
	assert.Equal(t, LogLevelFlag("error"), c.LogLevel)
}

func Test_config_missingDefaultIsFine_explicitMissingIsNot(t *testing.T) {
	c, err := parse(t, filepath.Join(t.TempDir(), "absent.yaml"), "agent")
	require.NoError(t, err)
	assert.Equal(t, 1420, c.Agent.MTU, "defaults apply without a config file")

	_, err = parse(t, filepath.Join(t.TempDir(), "absent.yaml"), "--config", "/nonexistent/cheesecloth.yaml", "agent")
	require.Error(t, err)
}

func Test_config_explicitFile(t *testing.T) {
	path := writeConfig(t, "wg7:\n  mtu: 1300\n")
	c, err := parse(t, filepath.Join(t.TempDir(), "absent.yaml"), "--config", path, "agent")
	require.NoError(t, err)
	assert.Equal(t, 1300, c.Agent.MTU)
	assert.Equal(t, "wg7", c.Agent.Interface)
}

func Test_config_rejectsUnknownAndCommandLineOnlyKeys(t *testing.T) {
	_, err := parse(t, writeConfig(t, "wg7:\n  mtu: 1300\n  bogus: 1\n  cluster_port: 7946\n"), "agent")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown setting(s) bogus, cluster_port")

	_, err = parse(t, writeConfig(t, "wg7:\n  join-key: secret\n"), "agent")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "join-key")
	assert.Contains(t, err.Error(), "one-time secret")
	// commands without the flag never resolve it; the file is still refused
	for _, cmd := range []string{"status", "invite"} {
		_, err = parse(t, writeConfig(t, "wg7:\n  join-key: secret\n"), cmd)
		assert.ErrorContains(t, err, "one-time secret", cmd)
	}

	// a typo is reported even in a section this command does not act under
	_, err = parse(t, writeConfig(t, "wg7:\n  mtu: 1300\nwg8:\n  bogus: 1\n"), "--interface", "wg7", "agent")
	assert.ErrorContains(t, err, "unknown setting(s) bogus")

	_, err = parse(t, writeConfig(t, "wg7:\n  init: true\n"), "agent")
	require.Error(t, err, "the flag is gone; the key is unknown like any other")
	assert.Contains(t, err.Error(), "unknown setting(s) init")

	_, err = parse(t, writeConfig(t, "wg7:\n  version: true\n"), "agent")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown setting(s) version")

	_, err = parse(t, writeConfig(t, "wg7:\n  mtu: [1, 2]\n"), "agent")
	require.Error(t, err, "a value of the wrong shape is an error")

	_, err = parse(t, writeConfig(t, "not: valid: yaml\n"), "agent")
	require.Error(t, err)
}

func Test_config_sectionIsTheInterface(t *testing.T) {
	// the old flat format, and anything else that is not a section
	_, err := parse(t, writeConfig(t, "mtu: 1380\ninterface: wg7\n"), "agent")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "is not an interface section")
	assert.Contains(t, err.Error(), "keyed by interface name")

	_, err = parse(t, writeConfig(t, "wg7:\n  interface: wg8\n"), "agent")
	require.Error(t, err)
	assert.Contains(t, err.Error(), `"interface" cannot be set in section "wg7"`)
}

func Test_config_selectsSectionByInterface(t *testing.T) {
	path := writeConfig(t, "wg7:\n  mtu: 1380\nwg8:\n  mtu: 1300\n")

	c, err := parse(t, path, "--interface", "wg8", "agent")
	require.NoError(t, err)
	assert.Equal(t, 1300, c.Agent.MTU)
	assert.Equal(t, "wg8", c.Agent.Interface)

	// the flag may also come after the command, or be joined with =
	c, err = parse(t, path, "agent", "--interface=wg7")
	require.NoError(t, err)
	assert.Equal(t, 1380, c.Agent.MTU)

	// the operator commands choose the same way
	c, err = parse(t, path, "--interface", "wg8", "status")
	require.NoError(t, err)
	assert.Equal(t, "wg8", c.Status.Interface)

	// several sections and nothing to choose between them
	_, err = parse(t, path, "agent")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "the config file has sections for wg7, wg8")
	assert.Contains(t, err.Error(), "--interface")

	// an interface the file says nothing about leaves the defaults alone
	c, err = parse(t, path, "--interface", "wg9", "agent")
	require.NoError(t, err)
	assert.Equal(t, 1420, c.Agent.MTU)
	assert.Equal(t, "wg9", c.Agent.Interface)
}

func Test_config_emptyFile(t *testing.T) {
	// what a fresh install ships: every setting commented out
	for _, body := range []string{"", "# wgoverlay:\n#   mtu: 1380\n"} {
		c, err := parse(t, writeConfig(t, body), "agent")
		require.NoError(t, err)
		assert.Equal(t, 1420, c.Agent.MTU)
		assert.Equal(t, DefaultInterface, c.Agent.Interface)
	}
}

func Test_interfaceArg(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{nil, ""},
		{[]string{"agent"}, ""},
		{[]string{"--interface", "wg7"}, "wg7"},
		{[]string{"agent", "--interface=wg7"}, "wg7"},
		{[]string{"--interface"}, ""},
		{[]string{"status", "--mtu", "1300"}, ""},
	} {
		assert.Equal(t, tc.want, interfaceArg(tc.args), tc.args)
	}
}

func Test_noEnvironmentVariables(t *testing.T) {
	t.Setenv("CHEESECLOTH_MTU", "1300")
	t.Setenv("CHEESECLOTH_INTERFACE", "wgenv")
	c, err := parse(t, filepath.Join(t.TempDir(), "absent.yaml"), "agent")
	require.NoError(t, err)
	assert.Equal(t, 1420, c.Agent.MTU, "environment variables are not consulted")
	assert.Equal(t, "wgoverlay", c.Agent.Interface)
}
