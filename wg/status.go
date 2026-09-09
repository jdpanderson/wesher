package wg

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Report is a snapshot of a cheesecloth wireguard interface.
type Report struct {
	Interface  string         `json:"interface"`
	PublicKey  string         `json:"publicKey"`
	ListenPort int            `json:"listenPort"`
	Addrs      []netip.Prefix `json:"addrs"`
	Peers      []PeerReport   `json:"peers"`
}

// PeerReport is one peer of a Report.
type PeerReport struct {
	PublicKey           string         `json:"publicKey"`
	Endpoint            string         `json:"endpoint,omitempty"`
	AllowedIPs          []netip.Prefix `json:"allowedIPs"`
	LastHandshake       time.Time      `json:"lastHandshake"`
	ReceiveBytes        int64          `json:"receiveBytes"`
	TransmitBytes       int64          `json:"transmitBytes"`
	PersistentKeepalive time.Duration  `json:"persistentKeepalive"`
}

// OverlayAddr returns the peer's single-address allowed IP, if it has exactly
// one; the other allowed IPs are networks routed through the peer.
func (p PeerReport) OverlayAddr() (netip.Addr, bool) {
	var found netip.Addr
	n := 0
	for _, a := range p.AllowedIPs {
		if a.IsSingleIP() {
			found, n = a.Addr(), n+1
		}
	}
	return found, n == 1
}

// Routes lists the networks routed through the peer: its allowed IPs other than single addresses.
func (p PeerReport) Routes() []netip.Prefix {
	var out []netip.Prefix
	for _, a := range p.AllowedIPs {
		if !a.IsSingleIP() {
			out = append(out, a)
		}
	}
	return out
}

// Status reports on the wireguard interface iface. It needs the same privileges as the agent.
func Status(iface string) (*Report, error) {
	client, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("instantiating wireguard client: %w", err)
	}
	defer func() { _ = client.Close() }()
	return status(iface, client, &netlink.Handle{})
}

func status(iface string, client wgClient, nl netlinker) (*Report, error) {
	dev, err := client.Device(iface)
	if err != nil {
		return nil, fmt.Errorf("getting wireguard device %s: %w", iface, err)
	}
	link, err := nl.LinkByName(iface)
	if err != nil {
		return nil, fmt.Errorf("getting link %s: %w", iface, err)
	}
	addrs, err := nl.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return nil, fmt.Errorf("listing addresses of %s: %w", iface, err)
	}

	r := &Report{
		Interface:  dev.Name,
		PublicKey:  dev.PublicKey.String(),
		ListenPort: dev.ListenPort,
		Addrs:      make([]netip.Prefix, 0, len(addrs)),
		Peers:      make([]PeerReport, 0, len(dev.Peers)),
	}
	for _, a := range addrs {
		// the kernel adds an fe80:: address to every interface; only the overlay addresses are of interest
		if p, ok := prefixFromIPNet(a.IPNet); ok && !p.Addr().IsLinkLocalUnicast() {
			r.Addrs = append(r.Addrs, p)
		}
	}
	for _, p := range dev.Peers {
		r.Peers = append(r.Peers, peerReport(p))
	}
	return r, nil
}

func peerReport(p wgtypes.Peer) PeerReport {
	pr := PeerReport{
		PublicKey:           p.PublicKey.String(),
		AllowedIPs:          make([]netip.Prefix, 0, len(p.AllowedIPs)),
		LastHandshake:       p.LastHandshakeTime,
		ReceiveBytes:        p.ReceiveBytes,
		TransmitBytes:       p.TransmitBytes,
		PersistentKeepalive: p.PersistentKeepaliveInterval,
	}
	if p.Endpoint != nil {
		pr.Endpoint = p.Endpoint.String()
	}
	for i := range p.AllowedIPs {
		if pfx, ok := prefixFromIPNet(&p.AllowedIPs[i]); ok {
			pr.AllowedIPs = append(pr.AllowedIPs, pfx)
		}
	}
	return pr
}
