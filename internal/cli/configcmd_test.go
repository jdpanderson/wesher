package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runConfig parses args and runs the config command with its state kept in
// stateDir, returning what it printed.
func runConfig(t *testing.T, configPath, stateDir string, args ...string) (string, string, error) {
	t.Helper()
	c, err := parse(t, configPath, args...)
	require.NoError(t, err)
	c.Settings.stateDir = stateDir
	return captureOutput(t, func() error { return c.Settings.Run(c) })
}

// writeState puts a state file for iface in dir holding only the overlay
// network, which is all the config command reads back.
func writeState(t *testing.T, dir, iface, overlayNet string) {
	t.Helper()
	body := `{"seed":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","overlayNet":"` + overlayNet + `"}`
	require.NoError(t, os.WriteFile(filepath.Join(dir, iface+".json"), []byte(body), 0o600))
}

func Test_ConfigCmd_dumpsOneInterface(t *testing.T) {
	path := writeConfig(t, "wg7:\n  mtu: 1380\n  cluster-port: 17946\n")

	// told which interface, the command line applies on top of the file
	stdout, _, err := runConfig(t, path, t.TempDir(), "config", "--interface", "wg7", "--mtu", "9000")
	require.NoError(t, err)
	assert.Equal(t, "wg7:\n  cluster-port: 17946\n  mtu: 9000\n", stdout)
}

func Test_ConfigCmd_dumpTakesOverlayNetFromState(t *testing.T) {
	dir := t.TempDir()
	writeState(t, dir, "wg7", "10.42.0.0/16")
	path := writeConfig(t, "wg7:\n  mtu: 1380\n")

	stdout, _, err := runConfig(t, path, dir, "config", "--interface", "wg7")
	require.NoError(t, err)
	assert.Contains(t, stdout, "overlay-net: 10.42.0.0/16", "what the cluster told this node")

	// an overlay network given here wins, as it does for the agent
	stdout, _, err = runConfig(t, path, dir, "config", "--interface", "wg7", "--overlay-net", "10.9.0.0/16")
	require.NoError(t, err)
	assert.Contains(t, stdout, "overlay-net: 10.9.0.0/16")
}

func Test_ConfigCmd_dumpsEverySection(t *testing.T) {
	dir := t.TempDir()
	writeState(t, dir, "wg8", "10.42.0.0/16")
	path := writeConfig(t, "wg7:\n  mtu: 1380\nwg8:\n  cluster-port: 17946\n")

	// no --interface: every section, with what the state adds, and the
	// command line left out since no one section owns it
	stdout, _, err := runConfig(t, path, dir, "config", "--mtu", "9000")
	require.NoError(t, err)
	assert.Equal(t, "wg7:\n  mtu: 1380\nwg8:\n  cluster-port: 17946\n  overlay-net: 10.42.0.0/16\n", stdout)
}

func Test_ConfigCmd_dumpsDefaultInterfaceWithoutAFile(t *testing.T) {
	dir := t.TempDir()
	writeState(t, dir, DefaultInterface, "10.42.0.0/16")

	stdout, _, err := runConfig(t, filepath.Join(t.TempDir(), "absent.yaml"), dir, "config")
	require.NoError(t, err)
	assert.Equal(t, DefaultInterface+":\n  overlay-net: 10.42.0.0/16\n", stdout)
}

func Test_ConfigCmd_dumpsOnlyWhatDiffersFromTheDefaults(t *testing.T) {
	stdout, _, err := runConfig(t, filepath.Join(t.TempDir(), "absent.yaml"), t.TempDir(),
		"config", "--mtu", "1420", "--cluster-port", "7946", "--log-level", "warn")
	require.NoError(t, err)
	assert.Equal(t, DefaultInterface+": {}\n", stdout, "nothing is worth writing down")

	stdout, _, err = runConfig(t, filepath.Join(t.TempDir(), "absent.yaml"), t.TempDir(),
		"config", "--log-level", "debug", "--no-etc-hosts", "--join", "a.example.net")
	require.NoError(t, err)
	assert.Contains(t, stdout, "join:\n    - a.example.net")
	assert.Contains(t, stdout, "no-etc-hosts: true")
	assert.Contains(t, stdout, "log-level: debug")
}

func Test_ConfigCmd_initWritesAFreshFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "config.yaml")
	_, stderr, err := runConfig(t, path, t.TempDir(), "config", "--init", "--overlay-net", "10.42.0.0/24")
	require.NoError(t, err)
	assert.Contains(t, stderr, "wrote the "+DefaultInterface+" section")

	written, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, DefaultInterface+":\n  overlay-net: 10.42.0.0/24\n", string(written))

	// and the agent reads back what was written
	c, err := parse(t, path, "agent")
	require.NoError(t, err)
	assert.Equal(t, "10.42.0.0/24", c.Agent.OverlayNet.String())
	assert.Equal(t, DefaultInterface, c.Agent.Interface)
}

func Test_ConfigCmd_initKeepsWhatTheFileAlreadyHolds(t *testing.T) {
	// the file the package ships: every setting commented out
	shipped, err := os.ReadFile("../../dist/config.yaml")
	require.NoError(t, err)
	path := writeConfig(t, string(shipped))

	_, _, err = runConfig(t, path, t.TempDir(), "config", "--init", "--interface", "wg7", "--mtu", "1380")
	require.NoError(t, err)

	after, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Contains(t, string(after), string(shipped), "the comments survive verbatim")
	assert.Contains(t, string(after), "wg7:\n  mtu: 1380\n")

	// a second interface joins the first rather than replacing it
	_, _, err = runConfig(t, path, t.TempDir(), "config", "--init", "--interface", "wg8", "--cluster-port", "17946")
	require.NoError(t, err)
	sections, err := readSections(path)
	require.NoError(t, err)
	assert.Len(t, sections, 2)
	assert.Equal(t, 1380, sections["wg7"]["mtu"])
	assert.Equal(t, 17946, sections["wg8"]["cluster-port"])
}

func Test_ConfigCmd_initRefusesASectionThatExists(t *testing.T) {
	path := writeConfig(t, "wg7:\n  mtu: 1380\n")
	_, _, err := runConfig(t, path, t.TempDir(), "config", "--init", "--interface", "wg7")
	require.Error(t, err)
	assert.Contains(t, err.Error(), `already has a section for "wg7"`)
	assert.Contains(t, err.Error(), "cheesecloth config")

	after, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "wg7:\n  mtu: 1380\n", string(after), "the file is left alone")
}

func Test_ConfigCmd_survivesAFileOtherCommandsCannotChooseFrom(t *testing.T) {
	path := writeConfig(t, "wg7:\n  mtu: 1380\nwg8:\n  mtu: 1300\n")

	// every other command needs to be told which interface it acts on
	_, err := parse(t, path, "status")
	assert.ErrorContains(t, err, "the config file has sections for wg7, wg8")

	// the config command reports them all instead
	stdout, _, err := runConfig(t, path, t.TempDir(), "config")
	require.NoError(t, err)
	assert.Equal(t, "wg7:\n  mtu: 1380\nwg8:\n  mtu: 1300\n", stdout)
}
