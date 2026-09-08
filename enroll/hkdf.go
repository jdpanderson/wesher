package enroll

import (
	"crypto/hkdf"
	"hash"
)

// hkdfExpand is HKDF-SHA256 extract-and-expand; the standard library returns an
// error only for absurd lengths, which callers here never request.
func hkdfExpand(h func() hash.Hash, secret, salt []byte, info string, n int) []byte {
	out, err := hkdf.Key(h, secret, salt, info, n)
	if err != nil {
		panic("hkdf: " + err.Error())
	}
	return out
}
