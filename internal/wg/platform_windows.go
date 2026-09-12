//go:build windows

package wg

import "net"

// platform on Windows: no kernel WireGuard the agent could drive, so the
// device runs in this process on a Wintun adapter (wintun.dll next to the
// binary), and the stack is driven through the IP helper API.
func platform(Config) (device, linker, error) {
	return &userspaceDevice{}, winLinker{}, nil
}

// remove has nothing to do: the Wintun adapter belongs to the agent process
// and goes with it.
func remove(string) error { return nil }

// lookup finds a running interface by the agent's name; the adapter carries it.
func lookup(iface string) (string, linker, error) {
	if _, err := net.InterfaceByName(iface); err != nil {
		return "", nil, err
	}
	return iface, winLinker{}, nil
}
