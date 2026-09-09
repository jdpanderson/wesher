package common

import (
	"encoding/binary"
	"math"
	"net/netip"
)

// MaxHost is the highest overlay slot prefix can hold: slots run from 1 to
// MaxHost, leaving out the network address and, for IPv4, the broadcast
// address. Prefixes with more than 64 host bits are capped at 64.
func MaxHost(prefix netip.Prefix) uint64 {
	bits := prefix.Addr().BitLen() - prefix.Bits()
	if bits >= 64 {
		return math.MaxUint64 - 1
	}
	max := uint64(1)<<bits - 1
	if prefix.Addr().Is4() && max > 0 {
		max-- // broadcast
	}
	return max
}

// OverlayAddr is the address of slot host inside prefix; false if the slot
// does not fit.
func OverlayAddr(prefix netip.Prefix, host uint64) (netip.Addr, bool) {
	if host == 0 || host > MaxHost(prefix) {
		return netip.Addr{}, false
	}
	base := prefix.Masked().Addr()
	if base.Is4() {
		b := base.As4()
		binary.BigEndian.PutUint32(b[:], binary.BigEndian.Uint32(b[:])|uint32(host))
		return netip.AddrFrom4(b), true
	}
	b := base.As16()
	binary.BigEndian.PutUint64(b[8:], binary.BigEndian.Uint64(b[8:])|host)
	return netip.AddrFrom16(b), true
}
