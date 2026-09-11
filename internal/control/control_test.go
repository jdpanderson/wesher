package control

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeHandler struct {
	ttl  time.Duration
	uses int
}

func (f *fakeHandler) Invite(ttl time.Duration, uses int) (string, error) {
	f.ttl, f.uses = ttl, uses
	if uses <= 0 {
		return "", errors.New("uses must be positive")
	}
	return "TOKEN", nil
}

func (f *fakeHandler) Revoke(target string) (string, error) {
	if target == "ghost" {
		return "", errors.New("no such node")
	}
	return "IDENTITY-" + target, nil
}

func Test_control_roundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "w.sock")
	h := &fakeHandler{}
	srv, err := Listen(path, h)
	require.NoError(t, err)
	defer srv.Close()

	resp, err := Call(path, Request{Op: "invite", TTL: "10m", Uses: 2})
	require.NoError(t, err)
	assert.Equal(t, "TOKEN", resp.Token)
	assert.Equal(t, 10*time.Minute, h.ttl)
	assert.Equal(t, 2, h.uses)

	_, err = Call(path, Request{Op: "invite", TTL: "10m", Uses: 0})
	assert.ErrorContains(t, err, "uses must be positive")
	_, err = Call(path, Request{Op: "invite", TTL: "soon", Uses: 1})
	assert.ErrorContains(t, err, "invalid ttl")

	resp, err = Call(path, Request{Op: "revoke", Target: "node2"})
	require.NoError(t, err)
	assert.Equal(t, "IDENTITY-node2", resp.Identity)
	_, err = Call(path, Request{Op: "revoke", Target: "ghost"})
	assert.ErrorContains(t, err, "no such node")

	_, err = Call(path, Request{Op: "dance"})
	assert.ErrorContains(t, err, "unknown operation")

	srv.Close()
	_, err = Call(path, Request{Op: "invite", TTL: "1m", Uses: 1})
	assert.ErrorContains(t, err, "is it running")
}

func Test_Listen_replacesStaleSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "w.sock")
	first, err := Listen(path, &fakeHandler{})
	require.NoError(t, err)
	_ = first.ln.Close() // simulate an unclean exit that left the file behind
	second, err := Listen(path, &fakeHandler{})
	require.NoError(t, err)
	defer second.Close()
	_, err = Call(path, Request{Op: "invite", TTL: "1m", Uses: 1})
	assert.NoError(t, err)
}

func Test_Listen_refusesToReplaceAFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notes.txt")
	require.NoError(t, os.WriteFile(path, []byte("keep me"), 0o600))
	_, err := Listen(path, &fakeHandler{})
	assert.ErrorContains(t, err, "not a socket")
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "keep me", string(content))
}

func Test_DefaultSocket(t *testing.T) {
	assert.Equal(t, "/run/cheesecloth/wgoverlay.sock", DefaultSocket("wgoverlay"))
}
