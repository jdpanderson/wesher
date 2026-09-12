//go:build windows

package wg

import (
	"errors"
	"net"
	"net/netip"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// winLinker drives the Windows network stack through the IP helper API, as
// the official WireGuard client does; winipcfg is that client's wrapper.
type winLinker struct{}

func luidOf(iface string) (winipcfg.LUID, error) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return 0, err
	}
	return winipcfg.LUIDFromIndex(uint32(ifi.Index))
}

func (winLinker) SetAddr(iface string, addr netip.Prefix) error {
	luid, err := luidOf(iface)
	if err != nil {
		return err
	}
	if err := luid.AddIPAddress(addr); err != nil && !errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) {
		return err
	}
	return nil
}

// SetMTU sets the MTU of both address families; a family the adapter does
// not have (IPv6 disabled) is not an error.
func (winLinker) SetMTU(iface string, mtu int) error {
	luid, err := luidOf(iface)
	if err != nil {
		return err
	}
	for _, family := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
		ipif, err := luid.IPInterface(family)
		if errors.Is(err, windows.ERROR_NOT_FOUND) {
			continue
		}
		if err != nil {
			return err
		}
		ipif.NLMTU = uint32(mtu)
		if err := ipif.Set(); err != nil {
			return err
		}
	}
	return nil
}

// Up has nothing to do: a Wintun adapter is up for as long as the device
// holds it. It checks that this is so.
func (winLinker) Up(iface string) error {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return err
	}
	if ifi.Flags&net.FlagUp == 0 {
		return errors.New("the adapter is down")
	}
	return nil
}

func (winLinker) Addrs(iface string) ([]netip.Prefix, error) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, err
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return nil, err
	}
	out := make([]netip.Prefix, 0, len(addrs))
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			if p, ok := prefixFromIPNet(n); ok {
				out = append(out, p)
			}
		}
	}
	return out, nil
}

// Routes lists the routes through the interface that were added by hand or
// by a program, which is how the agent's arrive; the routes the stack derives
// from the interface's own addresses are left alone.
func (winLinker) Routes(iface string) ([]netip.Prefix, error) {
	luid, err := luidOf(iface)
	if err != nil {
		return nil, err
	}
	rows, err := winipcfg.GetIPForwardTable2(windows.AF_UNSPEC)
	if err != nil {
		return nil, err
	}
	return managedRoutes(rows, luid), nil
}

// managedRoutes picks the destinations of the routes through the interface
// with the given LUID that network management added.
func managedRoutes(rows []winipcfg.MibIPforwardRow2, luid winipcfg.LUID) []netip.Prefix {
	var out []netip.Prefix
	for i := range rows {
		row := &rows[i]
		if row.InterfaceLUID != luid || row.Protocol != winipcfg.RouteProtocolNetMgmt {
			continue
		}
		if dst := row.DestinationPrefix.Prefix(); dst.IsValid() {
			out = append(out, dst)
		}
	}
	return out
}

// nextHop is the on-link next hop for a route through the interface.
func nextHop(dst netip.Prefix) netip.Addr {
	if dst.Addr().Is4() {
		return netip.IPv4Unspecified()
	}
	return netip.IPv6Unspecified()
}

func (winLinker) AddRoute(iface string, dst netip.Prefix) error {
	luid, err := luidOf(iface)
	if err != nil {
		return err
	}
	if err := luid.AddRoute(dst, nextHop(dst), 0); err != nil && !errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) {
		return err
	}
	return nil
}

func (winLinker) DelRoute(iface string, dst netip.Prefix) error {
	luid, err := luidOf(iface)
	if err != nil {
		return err
	}
	if err := luid.DeleteRoute(dst, nextHop(dst)); err != nil && !errors.Is(err, windows.ERROR_NOT_FOUND) {
		return err
	}
	return nil
}
