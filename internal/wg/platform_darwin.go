//go:build darwin

package wg

import (
	"fmt"
	"net"
)

// platform on macOS: no kernel WireGuard, so the device runs in this process
// on a utun interface, and the stack is driven over ioctls and the routing
// socket.
func platform(Config) (device, linker, error) {
	return &userspaceDevice{}, bsdLinker{}, nil
}

// lookup finds the utun behind the agent's name from the record the agent
// published when it created the interface.
func lookup(iface string) (string, linker, error) {
	osName, err := osNameOf(iface)
	if err != nil {
		return "", nil, fmt.Errorf("no running agent for %s: %w", iface, err)
	}
	if _, err := net.InterfaceByName(osName); err != nil {
		return "", nil, err
	}
	return osName, bsdLinker{}, nil
}
