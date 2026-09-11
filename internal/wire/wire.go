// Package wire is the length-prefixed field encoding shared by everything that
// is signed or authenticated: each field as a 4-byte big-endian length and its
// bytes, so no field boundary is ambiguous.
package wire

import "encoding/binary"

// Fields encodes fields back to back, each length-prefixed.
func Fields(fields ...[]byte) []byte { return appendFields(nil, fields) }

// Canonical is Fields under a domain string terminated by a zero byte, so that
// records of different kinds can never have the same signed bytes.
func Canonical(domain string, fields ...[]byte) []byte {
	return appendFields(append([]byte(domain), 0), fields)
}

func appendFields(out []byte, fields [][]byte) []byte {
	for _, f := range fields {
		out = binary.BigEndian.AppendUint32(out, uint32(len(f)))
		out = append(out, f...)
	}
	return out
}
