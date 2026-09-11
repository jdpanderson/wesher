package overlay

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
)

// nodeMeta holds metadata sent over the cluster. AllowedIPs are extra
// networks reachable through the node. Identity is the node's membership
// identity and Signature binds Name, OverlayAddr, PubKey and AllowedIPs to it
// (see trust.MetaDigest); both are raw bytes so this package stays free of
// crypto dependencies.
type nodeMeta struct {
	OverlayAddr netip.Addr
	PubKey      string
	AllowedIPs  []netip.Prefix
	Identity    [32]byte
	Signature   []byte
}

// metaJSON is the wire form of nodeMeta: JSON like the rest of the protocol,
// with the identity as base64 rather than an array of numbers.
type metaJSON struct {
	OverlayAddr netip.Addr     `json:"overlay"`
	PubKey      string         `json:"wg"`
	AllowedIPs  []netip.Prefix `json:"routes,omitempty"`
	Identity    []byte         `json:"id"`
	Signature   []byte         `json:"sig"`
}

// Node holds the memberlist node structure
type Node struct {
	Name string
	Addr net.IP
	Meta []byte
	nodeMeta
}

// EncodeMeta encodes the node metadata to bytes, failing if they exceed limit.
func (n *Node) EncodeMeta(limit int) ([]byte, error) {
	m := n.nodeMeta
	b, err := json.Marshal(metaJSON{OverlayAddr: m.OverlayAddr, PubKey: m.PubKey, AllowedIPs: m.AllowedIPs, Identity: m.Identity[:], Signature: m.Signature})
	if err != nil {
		return nil, fmt.Errorf("encoding node meta: %w", err)
	}
	if len(b) > limit {
		return nil, fmt.Errorf("could not fit node metadata into %d bytes", limit)
	}
	return b, nil
}

// DecodeMeta decodes the node Meta field into its individual metadata fields.
func (n *Node) DecodeMeta() error {
	var m metaJSON
	if err := json.Unmarshal(n.Meta, &m); err != nil {
		return fmt.Errorf("decoding node meta: %w", err)
	}
	if len(m.Identity) != len(n.Identity) {
		return errors.New("decoding node meta: identity is not 32 bytes")
	}
	n.nodeMeta = nodeMeta{OverlayAddr: m.OverlayAddr, PubKey: m.PubKey, AllowedIPs: m.AllowedIPs, Signature: m.Signature}
	copy(n.Identity[:], m.Identity)
	return nil
}
