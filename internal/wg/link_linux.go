//go:build linux

package wg

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"syscall"

	"github.com/vishvananda/netlink"
)

// platform uses the kernel module whenever it is there: the probe is the
// link creation itself, which the kernel refuses with EOPNOTSUPP when it has
// no wireguard. Only then, or when asked, does the device run in this
// process. Either way the stack is driven over netlink.
func platform(cfg Config) (device, linker, error) {
	if !cfg.Userspace {
		_, err := kernelDevice{}.Create(cfg.Interface, cfg.MTU)
		switch {
		case err == nil:
			return kernelDevice{}, netlinkLinker{}, nil
		case errors.Is(err, syscall.EOPNOTSUPP):
			slog.Info("the kernel has no wireguard support; running the device in this process", "iface", cfg.Interface)
		default:
			return nil, nil, fmt.Errorf("creating interface %s: %w", cfg.Interface, err)
		}
	}
	return &userspaceDevice{}, netlinkLinker{}, nil
}

// lookup finds a running interface by the agent's name; the kernel keeps the
// name, so the operating system's is the same.
func lookup(iface string) (string, linker, error) {
	if _, err := netlink.LinkByName(iface); err != nil {
		return "", nil, err
	}
	return iface, netlinkLinker{}, nil
}

// kernelDevice is a WireGuard interface provided by the kernel module.
type kernelDevice struct{}

func (kernelDevice) Kind() string { return "kernel" }

func (kernelDevice) Create(name string, _ int) (string, error) {
	err := netlink.LinkAdd(&netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: name}})
	if err != nil && !errors.Is(err, os.ErrExist) {
		return "", err
	}
	return name, nil
}

func (kernelDevice) Delete(name string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		var notFound netlink.LinkNotFoundError
		if errors.As(err, &notFound) {
			return nil
		}
		return err
	}
	return netlink.LinkDel(link)
}

// netlinkLinker drives the Linux network stack over netlink.
type netlinkLinker struct{}

func (netlinkLinker) SetAddr(iface string, addr netip.Prefix) error {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return err
	}
	return netlink.AddrReplace(link, &netlink.Addr{IPNet: prefixToIPNet(addr)})
}

func (netlinkLinker) SetMTU(iface string, mtu int) error {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return err
	}
	return netlink.LinkSetMTU(link, mtu)
}

func (netlinkLinker) Up(iface string) error {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return err
	}
	return netlink.LinkSetUp(link)
}

func (netlinkLinker) Addrs(iface string) ([]netip.Prefix, error) {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return nil, err
	}
	addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return nil, err
	}
	out := make([]netip.Prefix, 0, len(addrs))
	for _, a := range addrs {
		if p, ok := prefixFromIPNet(a.IPNet); ok {
			out = append(out, p)
		}
	}
	return out, nil
}

func (netlinkLinker) Routes(iface string) ([]netip.Prefix, error) {
	routes, err := listRoutes(iface)
	if err != nil {
		return nil, err
	}
	out := make([]netip.Prefix, 0, len(routes))
	for i := range routes {
		if p, ok := prefixFromIPNet(routes[i].Dst); ok {
			out = append(out, p)
		}
	}
	return out, nil
}

func (netlinkLinker) AddRoute(iface string, dst netip.Prefix) error {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return err
	}
	err = netlink.RouteAdd(&netlink.Route{LinkIndex: link.Attrs().Index, Dst: prefixToIPNet(dst), Scope: netlink.SCOPE_LINK})
	if err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	return nil
}

// DelRoute deletes the routes to dst as the kernel lists them, so the
// deletion matches whatever scope and table the kernel gave them.
func (netlinkLinker) DelRoute(iface string, dst netip.Prefix) error {
	routes, err := listRoutes(iface)
	if err != nil {
		return err
	}
	for i := range routes {
		if p, ok := prefixFromIPNet(routes[i].Dst); !ok || p != dst {
			continue
		}
		if err := netlink.RouteDel(&routes[i]); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func listRoutes(iface string) ([]netlink.Route, error) {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return nil, err
	}
	return netlink.RouteList(link, netlink.FAMILY_ALL)
}
