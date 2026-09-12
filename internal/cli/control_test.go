package cli

import (
	"errors"
	"testing"
	"time"

	"github.com/jdpanderson/cheesecloth/internal/control"
	"github.com/jdpanderson/cheesecloth/internal/trust"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_controlFlags_socket(t *testing.T) {
	f := controlFlags{interfaceFlag: interfaceFlag{Interface: "wg1"}}
	assert.Equal(t, control.DefaultSocket("wg1"), f.socket())
	f.ControlSocket = "/tmp/x.sock"
	assert.Equal(t, "/tmp/x.sock", f.socket())
}

// fakeMembership stands in for the cluster behind the control socket.
type fakeMembership struct {
	id        *trust.Identity
	set       *trust.Set
	revoked   []trust.PublicKey
	revokeErr error
}

func newFakeMembership(t *testing.T) (*fakeMembership, *trust.Identity) {
	t.Helper()
	root, err := trust.NewIdentity()
	require.NoError(t, err)
	member, err := trust.NewIdentity()
	require.NoError(t, err)
	set := trust.NewSet(root.Public())
	set.Merge(trust.Records{Admissions: []trust.Admission{
		trust.SelfAdmit(root, "root", time.Now()),
		trust.Admit(root, member.Public(), member.DHPublic(), "member", 2, time.Now()),
	}})
	return &fakeMembership{id: root, set: set}, member
}

func (f *fakeMembership) Invite(ttl time.Duration, uses int) (string, error) {
	return "token-" + ttl.String(), nil
}
func (f *fakeMembership) Revoke(id trust.PublicKey) error {
	f.revoked = append(f.revoked, id)
	return f.revokeErr
}
func (f *fakeMembership) Trust() *trust.Set         { return f.set }
func (f *fakeMembership) Identity() trust.PublicKey { return f.id.Public() }

func Test_agentControl(t *testing.T) {
	m, member := newFakeMembership(t)
	ctl := agentControl{m}

	tok, err := ctl.Invite(5*time.Minute, 1)
	require.NoError(t, err)
	assert.Equal(t, "token-5m0s", tok)

	got, err := ctl.Revoke("member")
	require.NoError(t, err)
	assert.Equal(t, member.Public().String(), got, "resolved by name")

	got, err = ctl.Revoke(member.Public().String())
	require.NoError(t, err)
	assert.Equal(t, member.Public().String(), got, "given as an identity")
	assert.Equal(t, []trust.PublicKey{member.Public(), member.Public()}, m.revoked)

	_, err = ctl.Revoke("nobody")
	assert.ErrorContains(t, err, `no member named "nobody"`)
	_, err = ctl.Revoke("root")
	assert.ErrorContains(t, err, "refusing to revoke this node itself")
	_, err = ctl.Revoke(m.Identity().String())
	assert.ErrorContains(t, err, "refusing")

	m.revokeErr = errors.New("boom")
	_, err = ctl.Revoke("member")
	assert.ErrorContains(t, err, "boom")
}
