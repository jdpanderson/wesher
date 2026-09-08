package wg

import (
	"errors"
	"fmt"
	"hash/fnv"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/jdpanderson/wesher/common"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// wgClient is the subset of *wgctrl.Client used by State.
type wgClient interface {
	Device(name string) (*wgtypes.Device, error)
	ConfigureDevice(name string, cfg wgtypes.Config) error
}

// netlinker is the subset of *netlink.Handle used by State.
type netlinker interface {
	LinkAdd(netlink.Link) error
	LinkDel(netlink.Link) error
	LinkByName(string) (netlink.Link, error)
	AddrReplace(netlink.Link, *netlink.Addr) error
	LinkSetMTU(netlink.Link, int) error
	LinkSetUp(netlink.Link) error
	RouteAdd(*netlink.Route) error
	RouteDel(*netlink.Route) error
	RouteList(netlink.Link, int) ([]netlink.Route, error)
	AddrList(netlink.Link, int) ([]netlink.Addr, error)
}

// Config describes the wireguard interface a State manages.
type Config struct {
	Interface  string       // name of the wireguard interface to create
	Port       int          // wireguard listen port, also used as the peers' port
	OverlayNet netip.Prefix // network the overlay addresses are picked from
	Name       string       // local node name; hashed into the overlay address
	MTU        int          // interface MTU
	// PersistentKeepalive, when non-zero, makes every peer send keepalives at this
	// interval so NAT mappings stay open.
	PersistentKeepalive time.Duration
}

// State holds the configured state of a Wesher Wireguard interface.
type State struct {
	iface       string
	mtu         int
	keepalive   time.Duration
	client      wgClient
	nl          netlinker
	overlayNet  netip.Prefix
	OverlayAddr netip.Addr
	Port        int
	PrivKey     wgtypes.Key
	PubKey      wgtypes.Key
}

// New creates a new Wesher Wireguard state.
// The Wireguard keys are generated for every new interface.
// The interface must later be setup using SetUpInterface.
func New(cfg Config) (*State, *common.Node, error) {
	client, err := wgctrl.New()
	if err != nil {
		return nil, nil, fmt.Errorf("instantiating wireguard client: %w", err)
	}
	return newState(cfg, client, &netlink.Handle{})
}

func newState(cfg Config, client wgClient, nl netlinker) (*State, *common.Node, error) {
	privKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, nil, fmt.Errorf("generating private key: %w", err)
	}
	pubKey := privKey.PublicKey()

	state := State{
		iface:       cfg.Interface,
		mtu:         cfg.MTU,
		keepalive:   cfg.PersistentKeepalive,
		client:      client,
		nl:          nl,
		overlayNet:  cfg.OverlayNet,
		OverlayAddr: overlayAddr(cfg.OverlayNet, cfg.Name),
		Port:        cfg.Port,
		PrivKey:     privKey,
		PubKey:      pubKey,
	}
	slog.Debug("assigned overlay address", "addr", state.OverlayAddr)

	node := &common.Node{Name: cfg.Name}
	node.OverlayAddr = state.OverlayAddr
	node.PubKey = state.PubKey.String()

	return &state, node, nil
}

// overlayAddr picks the address for name inside prefix deterministically:
// the host bits are the tail of an FNV-1a 128 hash of the name.
func overlayAddr(prefix netip.Prefix, name string) netip.Addr {
	ip := prefix.Addr().AsSlice()

	h := fnv.New128a()
	h.Write([]byte(name))
	hb := h.Sum(nil)

	for i := 1; i <= (prefix.Addr().BitLen()-prefix.Bits())/8; i++ {
		ip[len(ip)-i] = hb[len(hb)-i]
	}

	addr, _ := netip.AddrFromSlice(ip) // ip is a valid 4- or 16-byte slice
	return addr
}

// DownInterface deletes the associated network interface; a missing interface is not an error.
func (s *State) DownInterface() error {
	link, err := s.nl.LinkByName(s.iface)
	if err != nil {
		var notFound netlink.LinkNotFoundError
		if errors.As(err, &notFound) {
			return nil
		}
		return fmt.Errorf("getting link for %s: %w", s.iface, err)
	}
	return s.nl.LinkDel(link)
}

// SetUpInterface creates and sets up the associated network interface.
func (s *State) SetUpInterface(nodes []common.Node) error {
	if err := s.nl.LinkAdd(&netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: s.iface}}); err != nil && !os.IsExist(err) {
		return fmt.Errorf("creating link %s: %w", s.iface, err)
	}

	peerCfgs, err := s.nodesToPeerConfigs(nodes)
	if err != nil {
		return fmt.Errorf("converting received node information to wireguard format: %w", err)
	}
	if err = s.client.ConfigureDevice(s.iface, wgtypes.Config{
		PrivateKey:   &s.PrivKey,
		ListenPort:   &s.Port,
		ReplacePeers: true,
		Peers:        peerCfgs,
	}); err != nil {
		return fmt.Errorf("setting wireguard configuration for %s: %w", s.iface, err)
	}

	link, err := s.nl.LinkByName(s.iface)
	if err != nil {
		return fmt.Errorf("getting link information for %s: %w", s.iface, err)
	}
	if err := s.nl.AddrReplace(link, &netlink.Addr{
		IPNet: addrToIPNet(s.OverlayAddr),
	}); err != nil {
		return fmt.Errorf("setting address for %s: %w", s.iface, err)
	}
	if err := s.nl.LinkSetMTU(link, s.mtu); err != nil {
		return fmt.Errorf("setting MTU for %s: %w", s.iface, err)
	}
	if err := s.nl.LinkSetUp(link); err != nil {
		return fmt.Errorf("enabling interface %s: %w", s.iface, err)
	}
	wanted := make(map[netip.Addr]bool, len(nodes))
	for _, node := range nodes {
		wanted[node.OverlayAddr] = true
		if err := s.nl.RouteAdd(&netlink.Route{
			LinkIndex: link.Attrs().Index,
			Dst:       addrToIPNet(node.OverlayAddr),
			Scope:     netlink.SCOPE_LINK,
		}); err != nil && !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("adding route %s to %s: %w", node.OverlayAddr, s.iface, err)
		}
	}

	return s.removeStaleRoutes(link, wanted)
}

// removeStaleRoutes deletes host routes to overlay addresses on link that no
// current peer owns. The route to our own address (the kernel adds one for
// IPv6 /128 addresses) is left alone.
func (s *State) removeStaleRoutes(link netlink.Link, wanted map[netip.Addr]bool) error {
	wanted[s.OverlayAddr] = true
	routes, err := s.nl.RouteList(link, netlink.FAMILY_ALL)
	if err != nil {
		return fmt.Errorf("listing routes on %s: %w", s.iface, err)
	}
	for i := range routes {
		route := &routes[i]
		if route.Dst == nil {
			continue
		}
		dst, ok := netip.AddrFromSlice(route.Dst.IP)
		if !ok {
			continue
		}
		dst = dst.Unmap()
		ones, _ := route.Dst.Mask.Size()
		if ones != dst.BitLen() || !s.overlayNet.Contains(dst) || wanted[dst] {
			continue
		}
		slog.Debug("removing stale route", "dst", dst, "iface", s.iface)
		if err := s.nl.RouteDel(route); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("removing route %s from %s: %w", dst, s.iface, err)
		}
	}
	return nil
}

// prefixFromIPNet converts a *net.IPNet to a netip.Prefix, unmapping IPv4-in-IPv6.
func prefixFromIPNet(n *net.IPNet) (netip.Prefix, bool) {
	if n == nil {
		return netip.Prefix{}, false
	}
	addr, ok := netip.AddrFromSlice(n.IP)
	if !ok {
		return netip.Prefix{}, false
	}
	ones, bits := n.Mask.Size()
	if bits == 128 && addr.Is4In6() {
		ones -= 96
	}
	return netip.PrefixFrom(addr.Unmap(), ones), true
}

func addrToIPNet(addr netip.Addr) *net.IPNet {
	return &net.IPNet{
		IP:   addr.AsSlice(),
		Mask: net.CIDRMask(addr.BitLen(), addr.BitLen()),
	}
}

func (s *State) nodesToPeerConfigs(nodes []common.Node) ([]wgtypes.PeerConfig, error) {
	peerCfgs := make([]wgtypes.PeerConfig, len(nodes))
	for i, node := range nodes {
		pubKey, err := wgtypes.ParseKey(node.PubKey)
		if err != nil {
			return nil, fmt.Errorf("parsing wireguard key: %w", err)
		}
		var keepalive *time.Duration
		if s.keepalive > 0 {
			keepalive = &s.keepalive
		}
		peerCfgs[i] = wgtypes.PeerConfig{
			PublicKey:                   pubKey,
			ReplaceAllowedIPs:           true,
			PersistentKeepaliveInterval: keepalive,
			Endpoint: &net.UDPAddr{
				IP:   node.Addr,
				Port: s.Port,
			},
			AllowedIPs: []net.IPNet{
				*addrToIPNet(node.OverlayAddr),
			},
		}
	}
	return peerCfgs, nil
}
