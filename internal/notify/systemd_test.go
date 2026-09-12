//go:build unix

package notify

import (
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// listen plays systemd: a unixgram socket named in NOTIFY_SOCKET.
func listen(t *testing.T) <-chan string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "notify.sock")
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	t.Setenv("NOTIFY_SOCKET", path)
	msgs := make(chan string, 8)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			msgs <- string(buf[:n])
		}
	}()
	return msgs
}

func recv(t *testing.T, msgs <-chan string) string {
	t.Helper()
	select {
	case m := <-msgs:
		return m
	case <-time.After(5 * time.Second):
		t.Fatal("no notification")
		return ""
	}
}

func Test_Systemd(t *testing.T) {
	msgs := listen(t)
	var n Notifier = Systemd{}
	require.NoError(t, n.Ready("2 peers"))
	assert.Equal(t, "READY=1\nSTATUS=2 peers", recv(t, msgs))
	require.NoError(t, n.Status("3 peers"))
	assert.Equal(t, "STATUS=3 peers", recv(t, msgs))
	require.NoError(t, n.Stopping())
	assert.Equal(t, "STOPPING=1", recv(t, msgs))
}

func Test_Systemd_noSocket(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "")
	assert.NoError(t, Systemd{}.Ready("ok"), "not under systemd: nothing to do")
	t.Setenv("NOTIFY_SOCKET", filepath.Join(t.TempDir(), "missing.sock"))
	assert.Error(t, Systemd{}.Ready("ok"))
}
