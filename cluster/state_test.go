package cluster

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/costela/wesher/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// useTempStatePaths points the state path template at a fresh temp dir for the test.
func useTempStatePaths(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	origTemplate := statePathTemplate
	statePathTemplate = filepath.Join(dir, "%s.json")
	t.Cleanup(func() { statePathTemplate = origTemplate })
	return dir
}

func testState() *state {
	return &state{
		ClusterKey: []byte("abcdefghijklmnopqrstuvwxyzABCDEF"),
		Nodes: []common.Node{{
			Name: "node",
			Addr: net.ParseIP("10.0.0.2"),
		}},
	}
}

func Test_state_save_load(t *testing.T) {
	useTempStatePaths(t)
	s := testState()
	require.NoError(t, s.save("test"))

	assert.Equal(t, s, loadState("test"))
}

func Test_state_save_unwritableDir(t *testing.T) {
	dir := useTempStatePaths(t)
	blocker := filepath.Join(dir, "blocker")
	require.NoError(t, os.WriteFile(blocker, nil, 0o600))
	statePathTemplate = filepath.Join(blocker, "%s.json")

	assert.Error(t, testState().save("test"))
}

func Test_loadState_missing(t *testing.T) {
	useTempStatePaths(t)
	assert.Equal(t, &state{}, loadState("test"))
}

func Test_LoadKey(t *testing.T) {
	useTempStatePaths(t)
	_, err := LoadKey("test")
	require.ErrorContains(t, err, "no cluster key stored")

	s := testState()
	require.NoError(t, s.save("test"))
	got, err := LoadKey("test")
	require.NoError(t, err)
	assert.Equal(t, s.ClusterKey, got)
}

func Test_loadState_malformed(t *testing.T) {
	dir := useTempStatePaths(t)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test.json"), []byte("{not json"), 0o600))

	assert.Equal(t, &state{}, loadState("test"), "malformed state must yield an empty state")
}

func Test_loadState_unreadable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read any file")
	}
	dir := useTempStatePaths(t)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test.json"), []byte("{}"), 0o000))

	assert.Equal(t, &state{}, loadState("test"))
}
