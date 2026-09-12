package wg

import (
	"bufio"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/tuntest"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// socketDir is a short-lived directory for sockets. t.TempDir() names the
// test in the path, which pushes a socket past the platform's path limit.
func socketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "wgu")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// testUserspace is a userspace device on a tun in memory, with its control
// socket in a temporary directory. tuns counts the interfaces created.
type testUserspace struct {
	*userspaceDevice
	sock string
	tuns int
	errs map[string]error // "tun" or "listen": injected failures
}

func newTestUserspace(t *testing.T) *testUserspace {
	t.Helper()
	useTempNameDir(t)
	tu := &testUserspace{sock: filepath.Join(socketDir(t), "u.sock"), errs: map[string]error{}}
	tu.userspaceDevice = &userspaceDevice{
		createTUN: func(name string, mtu int) (tun.Device, error) {
			assert.Equal(t, tunName("wgtest0"), name)
			assert.Equal(t, 1400, mtu)
			if err := tu.errs["tun"]; err != nil {
				return nil, err
			}
			tu.tuns++
			return tuntest.NewChannelTUN().TUN(), nil
		},
		listen: func(name string) (net.Listener, error) {
			assert.Equal(t, "wgtest0", name)
			if err := tu.errs["listen"]; err != nil {
				return nil, err
			}
			return net.Listen("unix", tu.sock)
		},
	}
	t.Cleanup(func() { _ = tu.Delete("wgtest0") })
	return tu
}

// uapi sends one request over the control socket and returns the response.
func (tu *testUserspace) uapi(t *testing.T, request string) string {
	t.Helper()
	c, err := net.DialTimeout("unix", tu.sock, 5*time.Second)
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	require.NoError(t, c.SetDeadline(time.Now().Add(5*time.Second)))
	_, err = io.WriteString(c, request)
	require.NoError(t, err)
	var sb strings.Builder
	r := bufio.NewReader(c)
	for {
		line, err := r.ReadString('\n')
		require.NoError(t, err)
		if line == "\n" {
			return sb.String()
		}
		sb.WriteString(line)
	}
}

func Test_userspaceDevice_lifecycle(t *testing.T) {
	tu := newTestUserspace(t)
	assert.Equal(t, "userspace", tu.Kind())
	require.NoError(t, tu.Delete("wgtest0"), "deleting a device that never ran is fine")

	osName, err := tu.Create("wgtest0", 1400)
	require.NoError(t, err)
	assert.Equal(t, "loopbackTun1", osName, "the tun's own name is what the stack is driven by")
	assert.Equal(t, 1, tu.tuns)

	// the control socket speaks the wireguard userspace protocol wgctrl uses
	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	resp := tu.uapi(t, "set=1\nprivate_key="+hex.EncodeToString(key[:])+"\n\n")
	assert.Equal(t, "errno=0\n", resp)
	resp = tu.uapi(t, "get=1\n\n")
	assert.Contains(t, resp, "private_key="+hex.EncodeToString(key[:])+"\n")
	assert.Contains(t, resp, "errno=0\n")

	again, err := tu.Create("wgtest0", 1400)
	require.NoError(t, err)
	assert.Equal(t, osName, again)
	assert.Equal(t, 1, tu.tuns, "a running device is kept")

	require.NoError(t, tu.Delete("wgtest0"))
	_, err = net.DialTimeout("unix", tu.sock, time.Second)
	assert.Error(t, err, "the control socket went with the device")
	require.NoError(t, tu.Delete("wgtest0"), "twice is fine")

	_, err = tu.Create("wgtest0", 1400)
	require.NoError(t, err, "and it can come back")
	assert.Equal(t, 2, tu.tuns)
}

func Test_userspaceDevice_restartsStoppedDevice(t *testing.T) {
	tu := newTestUserspace(t)
	_, err := tu.Create("wgtest0", 1400)
	require.NoError(t, err)
	tu.dev.Close() // as if the device had died on its own
	<-tu.dev.Wait()

	_, err = tu.Create("wgtest0", 1400)
	require.NoError(t, err)
	assert.Equal(t, 2, tu.tuns, "a stopped device is replaced")
	assert.Contains(t, tu.uapi(t, "get=1\n\n"), "errno=0\n")
}

func Test_userspaceDevice_errors(t *testing.T) {
	boom := errors.New("boom")
	tu := newTestUserspace(t)

	tu.errs["tun"] = boom
	_, err := tu.Create("wgtest0", 1400)
	require.ErrorIs(t, err, boom)
	assert.Contains(t, err.Error(), "creating tun interface")
	delete(tu.errs, "tun")

	tu.errs["listen"] = boom
	_, err = tu.Create("wgtest0", 1400)
	require.ErrorIs(t, err, boom)
	assert.Contains(t, err.Error(), "opening the wireguard control socket")
	assert.Nil(t, tu.dev, "nothing is left running after a failed start")
	delete(tu.errs, "listen")

	_, err = tu.Create("wgtest0", 1400)
	require.NoError(t, err, "the failures left nothing behind")
}
