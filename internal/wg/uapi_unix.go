//go:build unix

package wg

import (
	"net"

	"golang.zx2c4.com/wireguard/ipc"
)

// uapiListen opens the control socket wgctrl and wg(8) look for:
// /var/run/wireguard/<name>.sock.
func uapiListen(name string) (net.Listener, error) {
	f, err := ipc.UAPIOpen(name)
	if err != nil {
		return nil, err
	}
	return ipc.UAPIListen(name, f)
}
