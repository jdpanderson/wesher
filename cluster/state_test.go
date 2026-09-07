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

// useTempStatePaths points both state paths at a fresh temp dir for the test.
func useTempStatePaths(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	origTemplate, origDeprecated := statePathTemplate, deprecatedStatePath
	statePathTemplate = filepath.Join(dir, "%s.json")
	deprecatedStatePath = filepath.Join(dir, "state.json")
	t.Cleanup(func() {
		statePathTemplate, deprecatedStatePath = origTemplate, origDeprecated
	})
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

	loaded := &state{}
	loadState(loaded, "test")
	assert.Equal(t, s, loaded)
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
	loaded := &state{}
	loadState(loaded, "test")
	assert.Equal(t, &state{}, loaded)
}

func Test_loadState_deprecatedPath(t *testing.T) {
	useTempStatePaths(t)
	s := testState()
	require.NoError(t, s.save("state")) // writes to <dir>/state.json, the deprecated path

	loaded := &state{}
	loadState(loaded, "test")
	assert.Equal(t, s, loaded)
}

func Test_loadState_malformed(t *testing.T) {
	dir := useTempStatePaths(t)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test.json"), []byte("{not json"), 0o600))

	loaded := &state{ClusterKey: []byte("keep")}
	loadState(loaded, "test")
	assert.Equal(t, []byte("keep"), loaded.ClusterKey, "malformed state must not clobber existing state")
}

func Test_loadState_unreadable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read any file")
	}
	dir := useTempStatePaths(t)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test.json"), []byte("{}"), 0o000))

	loaded := &state{ClusterKey: []byte("keep")}
	loadState(loaded, "test")
	assert.Equal(t, []byte("keep"), loaded.ClusterKey)
}
