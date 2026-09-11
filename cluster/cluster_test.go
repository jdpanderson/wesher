package cluster

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/hashicorp/memberlist"
	"github.com/jdpanderson/cheesecloth/trust"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Unit tests of the memberlist delegate on a one-node cluster; the gossip
// paths between nodes are covered by the integration tests.

func recordJSON(t *testing.T, m recordMsg) []byte {
	t.Helper()
	b, err := json.Marshal(m)
	require.NoError(t, err)
	return b
}

// drainBroadcasts empties the transmit queue, which hands out each record a few times.
func drainBroadcasts(c *Cluster) {
	for i := 0; i < 20 && len(c.GetBroadcasts(0, 1<<16)) > 0; i++ {
	}
}

func Test_Cluster_NotifyMsg(t *testing.T) {
	useTempStatePaths(t)
	a := rootCluster(t, "a", "127.0.0.1", freePort(t))
	defer a.Leave()
	drain(a.Members())

	a.NotifyMsg([]byte("garbage")) // ignored
	a.NotifyMsg([]byte("{}"))      // neither record kind: ignored

	j := testIdentity(t)
	adm := trust.Admit(a.id, j.Public(), j.DHPublic(), "j", 2, time.Now())
	tampered := adm
	tampered.Name = "x"
	a.NotifyMsg(recordJSON(t, recordMsg{Admission: &tampered}))
	assert.False(t, a.Trust().Valid(j.Public()), "a record with a bad signature is rejected")

	a.NotifyMsg(recordJSON(t, recordMsg{Admission: &adm}))
	assert.True(t, a.Trust().Valid(j.Public()))
	assert.NotEmpty(t, a.GetBroadcasts(0, 1<<16), "a record that changed the set is re-broadcast")
	drainBroadcasts(a)
	a.NotifyMsg(recordJSON(t, recordMsg{Admission: &adm}))
	assert.Empty(t, a.GetBroadcasts(0, 1<<16), "a record already known is not")

	rootRev := trust.Revoke(j, a.Identity(), time.Now())
	a.NotifyMsg(recordJSON(t, recordMsg{Revocation: &rootRev}))
	assert.True(t, a.Trust().Valid(a.Identity()), "the root cannot be revoked")

	rev := trust.Revoke(a.id, j.Public(), time.Now())
	a.NotifyMsg(recordJSON(t, recordMsg{Revocation: &rev}))
	assert.False(t, a.Trust().Valid(j.Public()))
	assert.NotEmpty(t, a.GetBroadcasts(0, 1<<16))
}

func Test_Cluster_state_pushPull(t *testing.T) {
	useTempStatePaths(t)
	a := rootCluster(t, "a", "127.0.0.1", freePort(t))
	defer a.Leave()
	drain(a.Members())

	var rs trust.Records
	require.NoError(t, json.Unmarshal(a.LocalState(true), &rs))
	require.Len(t, rs.Admissions, 1)
	assert.Equal(t, a.Identity(), rs.Admissions[0].Identity)

	a.MergeRemoteState([]byte("garbage"), false) // ignored
	k := testIdentity(t)
	adm := trust.Admit(a.id, k.Public(), k.DHPublic(), "k", 3, time.Now())
	remote, err := json.Marshal(trust.Records{Admissions: []trust.Admission{adm}})
	require.NoError(t, err)
	a.MergeRemoteState(remote, false)
	assert.True(t, a.Trust().Valid(k.Public()))
	a.MergeRemoteState(remote, false) // nothing new: no save, no signal

	// the merged record was persisted
	b, err := Load("a", false)
	require.NoError(t, err)
	assert.Len(t, b.Records.Admissions, 2)
}

func Test_Cluster_NodeMeta_and_Conflict(t *testing.T) {
	useTempStatePaths(t)
	a := rootCluster(t, "a", "127.0.0.1", freePort(t))
	defer a.Leave()

	assert.Nil(t, a.NodeMeta(1), "metadata that does not fit is not sent")
	assert.NotEmpty(t, a.NodeMeta(memberlist.MetaMaxSize))
	a.NotifyConflict(&memberlist.Node{Name: "a"}, &memberlist.Node{Name: "a"}) // only logs
}

func Test_Cluster_Join(t *testing.T) {
	useTempStatePaths(t)
	a := rootCluster(t, "a", "127.0.0.1", freePort(t))
	defer a.Leave()

	require.NoError(t, a.Join(nil), "nothing to join and nothing remembered: a cluster of one")
	err := a.Join([]string{"127.0.0.1:1"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "joining cluster")
}

func Test_recordBroadcast(t *testing.T) {
	b := recordBroadcast{name: "adm:x", msg: []byte("m")}
	assert.Equal(t, "adm:x", b.Name())
	assert.Equal(t, []byte("m"), b.Message())
	assert.False(t, b.Invalidates(recordBroadcast{name: "adm:x"}), "the queue de-duplicates by name; records never invalidate each other")
	b.Finished()
}

func Test_Cluster_admit_refusesTakenName(t *testing.T) {
	useTempStatePaths(t)
	a := rootCluster(t, "a", "127.0.0.1", freePort(t))
	defer a.Leave()

	j := testIdentity(t)
	_, _, err := a.admit(j.Public(), j.DHPublic(), "a")
	assert.ErrorContains(t, err, `named "a" already exists`)
	adm, _, err := a.admit(j.Public(), j.DHPublic(), "j")
	require.NoError(t, err)
	assert.Equal(t, uint64(2), adm.Host)
	// the same identity may enrol again under its name
	again, _, err := a.admit(j.Public(), j.DHPublic(), "j")
	require.NoError(t, err)
	assert.Equal(t, uint64(2), again.Host, "its slot is reused")
	k := testIdentity(t)
	_, _, err = a.admit(k.Public(), k.DHPublic(), "j")
	assert.ErrorContains(t, err, "already exists")
}
