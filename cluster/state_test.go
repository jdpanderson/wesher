package cluster

import (
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/jdpanderson/wesher/common"
	"github.com/jdpanderson/wesher/trust"
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

func testIdentity(t *testing.T) *trust.Identity {
	t.Helper()
	id, err := trust.NewIdentity()
	require.NoError(t, err)
	return id
}

func Test_state_save_load(t *testing.T) {
	useTempStatePaths(t)
	id := testIdentity(t)
	root := id.Public()
	s := &state{
		Seed:    id.Seed(),
		Root:    &root,
		Records: trust.Records{Admissions: []trust.Admission{trust.SelfAdmit(id, "root", unixTime(nil))}},
		Nodes:   []common.Node{{Name: "node", Addr: net.ParseIP("10.0.0.2")}},
	}
	require.NoError(t, s.save("test"))
	assert.Equal(t, s, loadState("test"))
}

func Test_state_save_unwritableDir(t *testing.T) {
	dir := useTempStatePaths(t)
	blocker := filepath.Join(dir, "blocker")
	require.NoError(t, os.WriteFile(blocker, nil, 0o600))
	statePathTemplate = filepath.Join(blocker, "%s.json")
	assert.Error(t, (&state{}).save("test"))
}

func Test_loadState_missingOrBroken(t *testing.T) {
	dir := useTempStatePaths(t)
	assert.Equal(t, &state{}, loadState("test"))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test.json"), []byte("{not json"), 0o600))
	assert.Equal(t, &state{}, loadState("test"), "malformed state must yield an empty state")
}

func Test_Load_createsAndKeepsIdentity(t *testing.T) {
	dir := useTempStatePaths(t)
	b, err := Load("test", false)
	require.NoError(t, err)
	assert.False(t, b.Enrolled())
	assert.FileExists(t, filepath.Join(dir, "test.json"), "identity persisted right away")

	again, err := Load("test", false)
	require.NoError(t, err)
	assert.Equal(t, b.Identity.Public(), again.Identity.Public(), "same identity on restart")

	fresh, err := Load("test", true)
	require.NoError(t, err)
	assert.NotEqual(t, b.Identity.Public(), fresh.Identity.Public(), "--init starts over")

	// a pre-identity (shared key era) state file is simply superseded
	require.NoError(t, os.WriteFile(filepath.Join(dir, "old.json"), []byte(`{"ClusterKey":"abc","Nodes":[]}`), 0o600))
	old, err := Load("old", false)
	require.NoError(t, err)
	assert.False(t, old.Enrolled())
}

func Test_Bootstrap_initAndEnrol(t *testing.T) {
	useTempStatePaths(t)
	b, err := Load("test", true)
	require.NoError(t, err)
	b.InitRoot("root", nil)
	assert.True(t, b.Enrolled())
	assert.Equal(t, b.Identity.Public(), b.Root)
	require.Len(t, b.Records.Admissions, 1)
	set := trust.NewSet(b.Root)
	set.Merge(b.Records)
	assert.True(t, set.Valid(b.Identity.Public()))

	other := testIdentity(t)
	j, err := Load("joiner", true)
	require.NoError(t, err)
	adm := trust.Admit(other, j.Identity.Public(), j.Identity.DHPublic(), "joiner", unixTime(nil))
	j.Enrol(other.Public(), trust.Records{Admissions: []trust.Admission{trust.SelfAdmit(other, "o", unixTime(nil)), adm}})
	assert.True(t, j.Enrolled())
	assert.Equal(t, other.Public(), j.Root)
}

func Test_KnownNodes(t *testing.T) {
	useTempStatePaths(t)
	assert.Empty(t, KnownNodes("test"))

	good := common.Node{Name: "good", Addr: net.ParseIP("192.0.2.1")}
	good.OverlayAddr = netip.MustParseAddr("10.0.0.1")
	good.PubKey = "pk"
	meta, err := good.EncodeMeta(512)
	require.NoError(t, err)
	good.Meta = meta
	bad := common.Node{Name: "bad", Addr: net.ParseIP("192.0.2.2"), Meta: []byte("garbage")}
	require.NoError(t, (&state{Nodes: []common.Node{good, bad}}).save("test"))

	got := KnownNodes("test")
	require.Len(t, got, 1)
	assert.Equal(t, "good", got[0].Name)
	assert.Equal(t, "10.0.0.1", got[0].OverlayAddr.String())
}
