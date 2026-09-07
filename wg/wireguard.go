package wg

import (
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"net/netip"
	"os"

	"github.com/costela/wesher/common"
	"github.com/sirupsen/logrus"
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
}

// State holds the configured state of a Wesher Wireguard interface.
type State struct {
	iface       string
	client      wgClient
	nl          netlinker
	OverlayAddr netip.Addr
	Port        int
	PrivKey     wgtypes.Key
	PubKey      wgtypes.Key
}

// New creates a new Wesher Wireguard state.
// The Wireguard keys are generated for every new interface.
// The interface must later be setup using SetUpInterface.
func New(iface string, port int, prefix netip.Prefix, name string) (*State, *common.Node, error) {
	client, err := wgctrl.New()
	if err != nil {
		return nil, nil, fmt.Errorf("instantiating wireguard client: %w", err)
	}
	return newState(iface, port, prefix, name, client, &netlink.Handle{})
}

func newState(iface string, port int, prefix netip.Prefix, name string, client wgClient, nl netlinker) (*State, *common.Node, error) {
	privKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, nil, fmt.Errorf("generating private key: %w", err)
	}
	pubKey := privKey.PublicKey()

	state := State{
		iface:   iface,
		client:  client,
		nl:      nl,
		Port:    port,
		PrivKey: privKey,
		PubKey:  pubKey,
	}
	if err := state.assignOverlayAddr(prefix, name); err != nil {
		return nil, nil, fmt.Errorf("assigning overlay address: %w", err)
	}

	node := &common.Node{}
	node.OverlayAddr = state.OverlayAddr
	node.PubKey = state.PubKey.String()

	return &state, node, nil
}

// assignOverlayAddr assigns a new address to the interface.
// The address is assigned inside the provided network and depends on the
// provided name deterministically.
// Currently, the address is assigned by hashing the name and mapping that
// hash in the target network space.
func (s *State) assignOverlayAddr(prefix netip.Prefix, name string) error {
	ip := prefix.Addr().AsSlice()

	h := fnv.New128a()
	h.Write([]byte(name))
	hb := h.Sum(nil)

	for i := 1; i <= (prefix.Addr().BitLen()-prefix.Bits())/8; i++ {
		ip[len(ip)-i] = hb[len(hb)-i]
	}

	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return fmt.Errorf("could not create IP from %q", ip)
	}

	logrus.Debugf("assigned overlay address: %s", addr)

	s.OverlayAddr = addr

	return nil
}

// DownInterface shuts down the associated network interface.
func (s *State) DownInterface() error {
	if _, err := s.client.Device(s.iface); err != nil {
		if os.IsNotExist(err) {
			return nil // device already gone; noop
		}
		return fmt.Errorf("getting device %s: %w", s.iface, err)
	}
	link, err := s.nl.LinkByName(s.iface)
	if err != nil {
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
	if err := s.client.ConfigureDevice(s.iface, wgtypes.Config{
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
	// TODO: make MTU configurable?
	if err := s.nl.LinkSetMTU(link, 1420); err != nil {
		return fmt.Errorf("setting MTU for %s: %w", s.iface, err)
	}
	if err := s.nl.LinkSetUp(link); err != nil {
		return fmt.Errorf("enabling interface %s: %w", s.iface, err)
	}
	for _, node := range nodes {
		if err := s.nl.RouteAdd(&netlink.Route{
			LinkIndex: link.Attrs().Index,
			Dst:       addrToIPNet(node.OverlayAddr),
			Scope:     netlink.SCOPE_LINK,
		}); err != nil && !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("adding route %s to %s: %w", node.OverlayAddr, s.iface, err)
		}
	}

	return nil
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
		peerCfgs[i] = wgtypes.PeerConfig{
			PublicKey:         pubKey,
			ReplaceAllowedIPs: true,
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
