package overlay

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
)

// Node is a member as memberlist sees it, plus the metadata it gossips.
// Meta is the encoded form, which is what is persisted; EncodeMeta produces it
// from the remaining fields and DecodeMeta fills them from it. AllowedIPs are
// extra networks reachable through the node. Identity is the node's
// membership identity and Signature binds Name, OverlayAddr, PubKey and
// AllowedIPs to it (see trust.MetaDigest); both are raw bytes so this package
// stays free of crypto dependencies.
type Node struct {
	Name string
	Addr netip.Addr // where memberlist reaches the node
	Meta []byte

	OverlayAddr netip.Addr     `json:"-"`
	PubKey      string         `json:"-"`
	AllowedIPs  []netip.Prefix `json:"-"`
	Identity    [32]byte       `json:"-"`
	Signature   []byte         `json:"-"`
}

// metaJSON is the wire form of the metadata: JSON like the rest of the
// protocol, with the identity as base64 rather than an array of numbers.
type metaJSON struct {
	OverlayAddr netip.Addr     `json:"overlay"`
	PubKey      string         `json:"wg"`
	AllowedIPs  []netip.Prefix `json:"routes,omitempty"`
	Identity    []byte         `json:"id"`
	Signature   []byte         `json:"sig"`
}

// EncodeMeta encodes the node metadata to bytes, failing if they exceed limit.
func (n *Node) EncodeMeta(limit int) ([]byte, error) {
	b, err := json.Marshal(metaJSON{OverlayAddr: n.OverlayAddr, PubKey: n.PubKey, AllowedIPs: n.AllowedIPs, Identity: n.Identity[:], Signature: n.Signature})
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
	n.OverlayAddr, n.PubKey, n.AllowedIPs, n.Signature = m.OverlayAddr, m.PubKey, m.AllowedIPs, m.Signature
	copy(n.Identity[:], m.Identity)
	return nil
}
