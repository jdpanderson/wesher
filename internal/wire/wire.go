// Package wire is the canonical byte encoding shared by everything that is
// signed or authenticated: a domain string terminated by a zero byte, then each
// field as a 4-byte big-endian length and its bytes, so that records of
// different kinds can never have the same bytes and no field boundary is
// ambiguous.
package wire

import "encoding/binary"

// Canonical encodes fields under domain.
func Canonical(domain string, fields ...[]byte) []byte {
	out := append([]byte(domain), 0)
	for _, f := range fields {
		out = binary.BigEndian.AppendUint32(out, uint32(len(f)))
		out = append(out, f...)
	}
	return out
}
