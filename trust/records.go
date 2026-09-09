package trust

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"time"
)

// Admission says that Admitter vouches for Identity as a member and assigns
// it Host, its slot in the overlay network (the host part of its address,
// never 0). The root admits itself (Admitter == Identity) and takes slot 1.
type Admission struct {
	Identity  PublicKey `json:"identity"`
	DHKey     DHKey     `json:"dhKey"`
	Name      string    `json:"name"`
	Host      uint64    `json:"host"`
	Admitter  PublicKey `json:"admitter"`
	IssuedAt  int64     `json:"issuedAt"` // unix seconds
	Signature []byte    `json:"signature"`
}

// RootHost is the overlay slot the root assigns itself.
const RootHost = 1

// Revocation says that Revoker withdraws Identity's membership.
type Revocation struct {
	Identity  PublicKey `json:"identity"`
	Revoker   PublicKey `json:"revoker"`
	IssuedAt  int64     `json:"issuedAt"`
	Signature []byte    `json:"signature"`
}

const (
	admissionDomain  = "cheesecloth/admission/v1"
	revocationDomain = "cheesecloth/revocation/v1"
	metaDomain       = "cheesecloth/meta/v1"
)

// canonical builds the signed bytes: domain, then each field length-prefixed.
func canonical(domain string, fields ...[]byte) []byte {
	out := append([]byte(domain), 0)
	for _, f := range fields {
		out = binary.BigEndian.AppendUint32(out, uint32(len(f)))
		out = append(out, f...)
	}
	return out
}

func i64(v int64) []byte { return binary.BigEndian.AppendUint64(nil, uint64(v)) }

func u64(v uint64) []byte { return binary.BigEndian.AppendUint64(nil, v) }

func (a *Admission) signedBytes() []byte {
	return canonical(admissionDomain, a.Identity[:], a.DHKey[:], []byte(a.Name), u64(a.Host), a.Admitter[:], i64(a.IssuedAt))
}

func (r *Revocation) signedBytes() []byte {
	return canonical(revocationDomain, r.Identity[:], r.Revoker[:], i64(r.IssuedAt))
}

// Admit creates an admission of (identity, dh, name) at overlay slot host,
// signed by admitter.
func Admit(admitter *Identity, identity PublicKey, dh DHKey, name string, host uint64, now time.Time) Admission {
	a := Admission{Identity: identity, DHKey: dh, Name: name, Host: host, Admitter: admitter.Public(), IssuedAt: now.Unix()}
	a.Signature = admitter.Sign(a.signedBytes())
	return a
}

// SelfAdmit creates the root record for id.
func SelfAdmit(id *Identity, name string, now time.Time) Admission {
	return Admit(id, id.Public(), id.DHPublic(), name, RootHost, now)
}

// Revoke creates a revocation of identity signed by revoker.
func Revoke(revoker *Identity, identity PublicKey, now time.Time) Revocation {
	r := Revocation{Identity: identity, Revoker: revoker.Public(), IssuedAt: now.Unix()}
	r.Signature = revoker.Sign(r.signedBytes())
	return r
}

// VerifySignature checks that the admitter signed the record.
func (a *Admission) VerifySignature() error {
	if a.Name == "" {
		return errors.New("admission without a name")
	}
	if a.Host == 0 {
		return errors.New("admission without an overlay slot")
	}
	if !Verify(a.Admitter, a.signedBytes(), a.Signature) {
		return errors.New("admission signature does not verify")
	}
	return nil
}

// VerifySignature checks that the revoker signed the record.
func (r *Revocation) VerifySignature() error {
	if !Verify(r.Revoker, r.signedBytes(), r.Signature) {
		return errors.New("revocation signature does not verify")
	}
	return nil
}

// MetaDigest is what a node signs to bind its (ephemeral) wireguard key,
// overlay address and the extra networks it routes to its identity in
// gossiped metadata.
func MetaDigest(name string, overlay netip.Addr, wgPubKey string, allowedIPs []netip.Prefix) []byte {
	fields := [][]byte{[]byte(name), overlay.AsSlice(), []byte(wgPubKey)}
	for _, p := range allowedIPs {
		fields = append(fields, append(p.Addr().AsSlice(), byte(p.Bits())))
	}
	return canonical(metaDomain, fields...)
}
