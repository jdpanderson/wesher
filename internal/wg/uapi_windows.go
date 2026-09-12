//go:build windows

package wg

import (
	"net"

	"golang.zx2c4.com/wireguard/ipc"
)

// uapiListen opens the named pipe wgctrl and wg(8) look for, restricted to
// administrators.
func uapiListen(name string) (net.Listener, error) { return ipc.UAPIListen(name) }
