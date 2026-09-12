package cluster

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jdpanderson/cheesecloth/internal/overlay"
	"github.com/jdpanderson/cheesecloth/internal/trust"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// useTempStatePaths is a fresh state directory for the test.
func useTempStatePaths(t *testing.T) string {
	t.Helper()
	return t.TempDir()
}

func testIdentity(t *testing.T) *trust.Identity {
	t.Helper()
	id, err := trust.NewIdentity()
	require.NoError(t, err)
	return id
}

func Test_state_save_load(t *testing.T) {
	dir := useTempStatePaths(t)
	id := testIdentity(t)
	root := id.Public()
	s := &state{
		Seed:    id.Seed(),
		Root:    &root,
		Records: trust.Records{Admissions: []trust.Admission{trust.SelfAdmit(id, "root", time.Now())}},
		Peers:   []overlay.Node{{Name: "node", Addr: netip.MustParseAddr("10.0.0.2")}},
	}
	require.NoError(t, s.save(statePath(dir, "test")))
	got, err := loadState(statePath(dir, "test"))
	require.NoError(t, err)
	assert.Equal(t, s, got)
}

func Test_Forget(t *testing.T) {
	dir := useTempStatePaths(t)
	_, err := Load(dir, "test", true)
	require.NoError(t, err)
	require.FileExists(t, statePath(dir, "test"))
	require.NoError(t, Forget(dir, "test"))
	assert.NoFileExists(t, statePath(dir, "test"))
	assert.NoError(t, Forget(dir, "test"), "nothing to forget is not an error")

	require.NoError(t, os.Mkdir(statePath(dir, "dir"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(statePath(dir, "dir"), "f"), nil, 0o600))
	assert.ErrorContains(t, Forget(dir, "dir"), "removing state")
}

func Test_state_save_unwritableDir(t *testing.T) {
	dir := useTempStatePaths(t)
	blocker := filepath.Join(dir, "blocker")
	require.NoError(t, os.WriteFile(blocker, nil, 0o600))
	assert.Error(t, (&state{}).save(statePath(blocker, "test")), "a file where the directory should be")
	_, err := Load(blocker, "test", true)
	assert.ErrorContains(t, err, "saving new identity")
}

func Test_loadState_missingOrBroken(t *testing.T) {
	dir := useTempStatePaths(t)
	got, err := loadState(statePath(dir, "test"))
	require.NoError(t, err)
	assert.Equal(t, &state{}, got, "no file is a fresh start")
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test.json"), []byte("{not json"), 0o600))
	_, err = loadState(statePath(dir, "test"))
	assert.ErrorContains(t, err, "decoding state")
	require.NoError(t, os.Mkdir(statePath(dir, "dir"), 0o700))
	_, err = loadState(statePath(dir, "dir"))
	assert.ErrorContains(t, err, "reading state")
}

// A state file whose seed is not one is refused, not replaced.
func Test_Load_refusesBadSeed(t *testing.T) {
	dir := useTempStatePaths(t)
	require.NoError(t, (&state{Seed: []byte("short")}).save(statePath(dir, "a")))
	_, err := Load(dir, "a", false)
	assert.ErrorContains(t, err, "loading identity")
}

// A damaged state file must not be replaced by a new identity: that would
// silently drop the node out of its cluster.
func Test_Load_refusesBrokenState(t *testing.T) {
	dir := useTempStatePaths(t)
	path := filepath.Join(dir, "test.json")
	require.NoError(t, os.WriteFile(path, []byte("{not json"), 0o600))
	_, err := Load(dir, "test", false)
	require.Error(t, err)
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "{not json", string(content), "the file is left for the operator")

	assert.Empty(t, KnownNodes(dir, "test"))
	_, ok := LocalIdentity(dir, "test")
	assert.False(t, ok)

	b, err := Load(dir, "test", true)
	require.NoError(t, err, "--init is the explicit way to start over")
	assert.False(t, b.Enrolled())
}

func Test_Load_createsAndKeepsIdentity(t *testing.T) {
	dir := useTempStatePaths(t)
	b, err := Load(dir, "test", false)
	require.NoError(t, err)
	assert.False(t, b.Enrolled())
	assert.FileExists(t, filepath.Join(dir, "test.json"), "identity persisted right away")

	again, err := Load(dir, "test", false)
	require.NoError(t, err)
	assert.Equal(t, b.Identity.Public(), again.Identity.Public(), "same identity on restart")

	fresh, err := Load(dir, "test", true)
	require.NoError(t, err)
	assert.NotEqual(t, b.Identity.Public(), fresh.Identity.Public(), "--init starts over")
}

func Test_Bootstrap_initAndEnrol(t *testing.T) {
	dir := useTempStatePaths(t)
	b, err := Load(dir, "test", true)
	require.NoError(t, err)
	b.InitRoot("root")
	assert.True(t, b.Enrolled())
	assert.Equal(t, b.Identity.Public(), b.Root)
	require.Len(t, b.Records.Admissions, 1)
	set := trust.NewSet(b.Root)
	set.Merge(b.Records)
	assert.True(t, set.Valid(b.Identity.Public()))

	other := testIdentity(t)
	j, err := Load(dir, "joiner", true)
	require.NoError(t, err)
	adm := trust.Admit(other, j.Identity.Public(), "joiner", 7, time.Now())
	records := trust.Records{Admissions: []trust.Admission{trust.SelfAdmit(other, "o", time.Now()), adm}}
	j.Enrol(other.Public(), records, netip.MustParsePrefix("10.42.0.0/16"))
	assert.True(t, j.Enrolled())
	assert.Equal(t, other.Public(), j.Root)
	assert.Equal(t, netip.MustParsePrefix("10.42.0.0/16"), j.OverlayNet, "the cluster's, as the member stated it")
	host, err := j.Host()
	require.NoError(t, err)
	assert.Equal(t, uint64(7), host)
}

func Test_KnownNodes(t *testing.T) {
	dir := useTempStatePaths(t)
	assert.Empty(t, KnownNodes(dir, "test"))

	good := overlay.Node{Name: "good", Addr: netip.MustParseAddr("192.0.2.1")}
	good.OverlayAddr = netip.MustParseAddr("10.0.0.1")
	good.PubKey = "pk"
	require.NoError(t, (&state{Peers: []overlay.Node{good}}).save(statePath(dir, "test")))

	got := KnownNodes(dir, "test")
	require.Len(t, got, 1)
	assert.Equal(t, good, got[0], "persisted with its metadata")

	require.NoError(t, os.WriteFile(statePath(dir, "broken"), []byte("{"), 0o600))
	assert.Empty(t, KnownNodes(dir, "broken"), "an unusable state file yields no peers")
}

func Test_LocalIdentity(t *testing.T) {
	dir := useTempStatePaths(t)
	_, ok := LocalIdentity(dir, "none")
	assert.False(t, ok)

	b, err := Load(dir, "a", true)
	require.NoError(t, err)
	id, ok := LocalIdentity(dir, "a")
	require.True(t, ok)
	assert.Equal(t, b.Identity.Public(), id)

	require.NoError(t, (&state{Seed: []byte("short")}).save(statePath(dir, "broken")))
	_, ok = LocalIdentity(dir, "broken")
	assert.False(t, ok)
}

func Test_Bootstrap_Host_withoutAdmission(t *testing.T) {
	dir := useTempStatePaths(t)
	b, err := Load(dir, "a", true)
	require.NoError(t, err)
	_, err = b.Host()
	assert.ErrorContains(t, err, "no admission record")
}

// A reader must never see a half-written state file.
func Test_state_save_atomic(t *testing.T) {
	dir := useTempStatePaths(t)
	id := testIdentity(t)
	root := id.Public()
	st := &state{Seed: id.Seed(), Root: &root, Records: trust.Records{Admissions: []trust.Admission{trust.SelfAdmit(id, "root", time.Now())}}}
	require.NoError(t, st.save(statePath(dir, "a")))

	// the writer reports through the channel: a test must not fail from another goroutine
	saved := make(chan error, 1)
	go func() {
		for i := 0; i < 200; i++ {
			st.Peers = append(st.Peers, overlay.Node{Name: fmt.Sprintf("n%d", i), Addr: netip.MustParseAddr("10.0.0.2")})
			if err := st.save(statePath(dir, "a")); err != nil {
				saved <- err
				return
			}
		}
		saved <- nil
	}()
	for {
		select {
		case err := <-saved:
			require.NoError(t, err)
			entries, err := os.ReadDir(dir)
			require.NoError(t, err)
			assert.Len(t, entries, 1, "no temp files left behind")
			return
		default:
			got, err := loadState(statePath(dir, "a"))
			require.NoError(t, err, "torn read")
			assert.Equal(t, id.Seed(), got.Seed)
		}
	}
}
