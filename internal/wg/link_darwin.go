//go:build darwin

package wg

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// bsdLinker drives the macOS network stack the way ifconfig(8) and route(8)
// do: addresses, MTU and flags over socket ioctls, routes over the routing
// socket.
type bsdLinker struct{}

// ioctl request numbers x/sys/unix does not define. Each encodes the size of
// its argument, so it doubles as a check on the struct layouts below.
const (
	siocAIFADDRIn6      = 0x8080691a // _IOW('i', 26, struct in6_aliasreq), 128 bytes
	nd6InfiniteLifetime = 0xffffffff
)

// ifreq is struct ifreq as SIOCGIFFLAGS and SIOCSIFFLAGS read it: the name,
// then a union of which the flags are the first 16 bits.
type ifreq struct {
	Name  [unix.IFNAMSIZ]byte
	Flags int16
	_     [14]byte
}

// ifAliasReq is struct ifaliasreq, the argument of SIOCAIFADDR.
type ifAliasReq struct {
	Name      [unix.IFNAMSIZ]byte
	Addr      unix.RawSockaddrInet4
	BroadAddr unix.RawSockaddrInet4 // the peer's address on a point-to-point interface
	Mask      unix.RawSockaddrInet4
}

// in6AliasReq is struct in6_aliasreq, the argument of SIOCAIFADDR_IN6.
type in6AliasReq struct {
	Name     [unix.IFNAMSIZ]byte
	Addr     unix.RawSockaddrInet6
	DstAddr  unix.RawSockaddrInet6
	Mask     unix.RawSockaddrInet6
	Flags    int32
	Lifetime struct {
		Expire, Preferred int64
		Vltime, Pltime    uint32
	}
}

func ifName(iface string) ([unix.IFNAMSIZ]byte, error) {
	var name [unix.IFNAMSIZ]byte
	if len(iface) >= len(name) {
		return name, fmt.Errorf("interface name %q is too long", iface)
	}
	copy(name[:], iface)
	return name, nil
}

func sockaddr4(addr netip.Addr) unix.RawSockaddrInet4 {
	return unix.RawSockaddrInet4{Len: unix.SizeofSockaddrInet4, Family: unix.AF_INET, Addr: addr.As4()}
}

func sockaddr6(addr netip.Addr) unix.RawSockaddrInet6 {
	return unix.RawSockaddrInet6{Len: unix.SizeofSockaddrInet6, Family: unix.AF_INET6, Addr: addr.As16()}
}

// mask4 and mask6 are the netmask of a prefix as an address.
func mask4(p netip.Prefix) netip.Addr {
	var m [4]byte
	copy(m[:], net.CIDRMask(p.Bits(), 32))
	return netip.AddrFrom4(m)
}

func mask6(p netip.Prefix) netip.Addr {
	var m [16]byte
	copy(m[:], net.CIDRMask(p.Bits(), 128))
	return netip.AddrFrom16(m)
}

// ioctl issues one request on a fresh socket of the given family.
func ioctl(family int, req uintptr, arg unsafe.Pointer) error {
	fd, err := unix.Socket(family, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), req, uintptr(arg)); errno != 0 {
		return errno
	}
	return nil
}

// SetAddr adds the address the way wg-quick(8) does on macOS: an IPv4
// address is its own point-to-point peer, an IPv6 address stands alone.
// Setting it again is fine.
func (bsdLinker) SetAddr(iface string, addr netip.Prefix) error {
	name, err := ifName(iface)
	if err != nil {
		return err
	}
	if addr.Addr().Is4() {
		req := ifAliasReq{Name: name, Addr: sockaddr4(addr.Addr()), BroadAddr: sockaddr4(addr.Addr()), Mask: sockaddr4(mask4(addr))}
		return ioctl(unix.AF_INET, unix.SIOCAIFADDR, unsafe.Pointer(&req))
	}
	req := in6AliasReq{Name: name, Addr: sockaddr6(addr.Addr()), Mask: sockaddr6(mask6(addr))}
	req.Lifetime.Vltime, req.Lifetime.Pltime = nd6InfiniteLifetime, nd6InfiniteLifetime
	return ioctl(unix.AF_INET6, siocAIFADDRIn6, unsafe.Pointer(&req))
}

func (bsdLinker) SetMTU(iface string, mtu int) error {
	name, err := ifName(iface)
	if err != nil {
		return err
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	return unix.IoctlSetIfreqMTU(fd, &unix.IfreqMTU{Name: name, MTU: int32(mtu)})
}

func (bsdLinker) Up(iface string) error {
	name, err := ifName(iface)
	if err != nil {
		return err
	}
	req := ifreq{Name: name}
	if err := ioctl(unix.AF_INET, unix.SIOCGIFFLAGS, unsafe.Pointer(&req)); err != nil {
		return err
	}
	if req.Flags&unix.IFF_UP != 0 {
		return nil
	}
	req.Flags |= unix.IFF_UP
	return ioctl(unix.AF_INET, unix.SIOCSIFFLAGS, unsafe.Pointer(&req))
}

func (bsdLinker) Addrs(iface string) ([]netip.Prefix, error) {
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

// Routes lists the static routes through the interface: the ones the agent
// adds, and leftovers of a previous run. The kernel's own routes for the
// interface's addresses are not static and are left alone.
func (bsdLinker) Routes(iface string) ([]netip.Prefix, error) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, err
	}
	rib, err := route.FetchRIB(unix.AF_UNSPEC, route.RIBTypeRoute, 0)
	if err != nil {
		return nil, err
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return nil, err
	}
	return staticRoutes(msgs, ifi.Index), nil
}

// staticRoutes picks the destinations of the static routes through the
// interface with the given index out of a routing table dump.
func staticRoutes(msgs []route.Message, index int) []netip.Prefix {
	var out []netip.Prefix
	for _, m := range msgs {
		rm, ok := m.(*route.RouteMessage)
		if !ok || rm.Index != index || rm.Flags&unix.RTF_STATIC == 0 {
			continue
		}
		if dst, ok := destination(rm); ok && !dst.Addr().IsMulticast() && !dst.Addr().IsLinkLocalUnicast() {
			out = append(out, dst)
		}
	}
	return out
}

// destination is the prefix a route message is about: its destination
// address masked by its netmask, or the address alone for a host route.
func destination(m *route.RouteMessage) (netip.Prefix, bool) {
	if len(m.Addrs) <= unix.RTAX_DST || m.Addrs[unix.RTAX_DST] == nil {
		return netip.Prefix{}, false
	}
	var mask route.Addr
	if len(m.Addrs) > unix.RTAX_NETMASK {
		mask = m.Addrs[unix.RTAX_NETMASK]
	}
	switch dst := m.Addrs[unix.RTAX_DST].(type) {
	case *route.Inet4Addr:
		bits := 32
		if nm, ok := mask.(*route.Inet4Addr); ok && m.Flags&unix.RTF_HOST == 0 {
			bits, _ = net.IPMask(nm.IP[:]).Size()
		}
		return netip.PrefixFrom(netip.AddrFrom4(dst.IP), bits), true
	case *route.Inet6Addr:
		bits := 128
		if nm, ok := mask.(*route.Inet6Addr); ok && m.Flags&unix.RTF_HOST == 0 {
			bits, _ = net.IPMask(nm.IP[:]).Size()
		}
		return netip.PrefixFrom(netip.AddrFrom16(dst.IP), bits), true
	}
	return netip.Prefix{}, false
}

var routeSeq atomic.Int32

// routeMessage is an add or delete of a static route to dst through the
// interface with the given index, as route(8) would send it.
func routeMessage(typ, index int, dst netip.Prefix) *route.RouteMessage {
	addrs := make([]route.Addr, unix.RTAX_MAX)
	if dst.Addr().Is4() {
		addrs[unix.RTAX_DST] = &route.Inet4Addr{IP: dst.Addr().As4()}
		addrs[unix.RTAX_NETMASK] = &route.Inet4Addr{IP: mask4(dst).As4()}
	} else {
		addrs[unix.RTAX_DST] = &route.Inet6Addr{IP: dst.Addr().As16()}
		addrs[unix.RTAX_NETMASK] = &route.Inet6Addr{IP: mask6(dst).As16()}
	}
	addrs[unix.RTAX_GATEWAY] = &route.LinkAddr{Index: index}
	return &route.RouteMessage{
		Version: unix.RTM_VERSION, Type: typ, Flags: unix.RTF_UP | unix.RTF_STATIC,
		Index: index, ID: uintptr(os.Getpid()), Seq: int(routeSeq.Add(1)), Addrs: addrs,
	}
}

// sendRoute writes one message to the routing socket; the kernel answers a
// refused change with an error on the write itself.
func sendRoute(m *route.RouteMessage) error {
	b, err := m.Marshal()
	if err != nil {
		return err
	}
	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	_, err = unix.Write(fd, b)
	return err
}

func (bsdLinker) AddRoute(iface string, dst netip.Prefix) error {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return err
	}
	if err := sendRoute(routeMessage(unix.RTM_ADD, ifi.Index, dst)); err != nil && !errors.Is(err, unix.EEXIST) {
		return err
	}
	return nil
}

func (bsdLinker) DelRoute(iface string, dst netip.Prefix) error {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return err
	}
	if err := sendRoute(routeMessage(unix.RTM_DELETE, ifi.Index, dst)); err != nil && !errors.Is(err, unix.ESRCH) {
		return err
	}
	return nil
}
