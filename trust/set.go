package trust

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"sync"
)

// Records is the wire and file form of a Set's contents.
type Records struct {
	Admissions  []Admission  `json:"admissions"`
	Revocations []Revocation `json:"revocations"`
}

// Set is the membership: a pinned root plus every signature-valid record seen.
// Validity is decided at query time from the root, so records may arrive in
// any order. Safe for concurrent use.
type Set struct {
	mu          sync.RWMutex
	root        PublicKey
	admissions  map[PublicKey]Admission
	revocations map[PublicKey]Revocation
}

// NewSet creates a set trusting root. The root's own record is added like any
// other, when it arrives.
func NewSet(root PublicKey) *Set {
	return &Set{root: root, admissions: map[PublicKey]Admission{}, revocations: map[PublicKey]Revocation{}}
}

// Root is the pinned root identity.
func (s *Set) Root() PublicKey { return s.root }

// ErrUntrustedRoot is returned for a self-signed admission of a non-root identity.
var ErrUntrustedRoot = errors.New("self-signed admission is not the pinned root")

// AddAdmission stores a signature-valid record. It reports whether the set
// changed; a record for an identity already present is kept only if newer.
func (s *Set) AddAdmission(a Admission) (bool, error) {
	if err := a.VerifySignature(); err != nil {
		return false, err
	}
	if a.Admitter == a.Identity && a.Identity != s.root {
		return false, ErrUntrustedRoot
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if cur, ok := s.admissions[a.Identity]; ok && cur.IssuedAt >= a.IssuedAt {
		return false, nil
	}
	s.admissions[a.Identity] = a
	return true, nil
}

// AddRevocation stores a signature-valid revocation; the root cannot be revoked.
func (s *Set) AddRevocation(r Revocation) (bool, error) {
	if err := r.VerifySignature(); err != nil {
		return false, err
	}
	if r.Identity == s.root {
		return false, errors.New("the root cannot be revoked")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.revocations[r.Identity]; ok {
		return false, nil
	}
	s.revocations[r.Identity] = r
	return true, nil
}

// Merge adds every record in rs, returning how many changed the set. Records
// that fail verification are skipped, not fatal: they came from the network.
func (s *Set) Merge(rs Records) int {
	changed := 0
	for _, a := range rs.Admissions {
		if ok, _ := s.AddAdmission(a); ok {
			changed++
		}
	}
	for _, r := range rs.Revocations {
		if ok, _ := s.AddRevocation(r); ok {
			changed++
		}
	}
	return changed
}

// Records returns the set's contents in a deterministic order.
func (s *Set) Records() Records {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rs := Records{}
	for _, a := range s.admissions {
		rs.Admissions = append(rs.Admissions, a)
	}
	for _, r := range s.revocations {
		rs.Revocations = append(rs.Revocations, r)
	}
	sort.Slice(rs.Admissions, func(i, j int) bool { return rs.Admissions[i].Identity.String() < rs.Admissions[j].Identity.String() })
	sort.Slice(rs.Revocations, func(i, j int) bool { return rs.Revocations[i].Identity.String() < rs.Revocations[j].Identity.String() })
	return rs
}

// Valid reports whether id is currently a member: not revoked by a member, and
// admitted by the root or by an identity that was a member at the time it
// issued the admission. The root is always valid.
func (s *Set) Valid(id PublicKey) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.valid(id, map[PublicKey]bool{})
}

func (s *Set) valid(id PublicKey, visiting map[PublicKey]bool) bool {
	return s.validAt(id, math.MaxInt64, visiting)
}

// validAt evaluates membership as of unix time at: revocations issued later
// are ignored, so an admission stays valid if its admitter was a member when
// it signed, even if the admitter was revoked afterwards.
func (s *Set) validAt(id PublicKey, at int64, visiting map[PublicKey]bool) bool {
	if id == s.root {
		return true
	}
	if visiting[id] {
		return false
	}
	visiting[id] = true
	defer delete(visiting, id)

	if rev, ok := s.revocations[id]; ok && rev.IssuedAt <= at && s.validAt(rev.Revoker, rev.IssuedAt, visiting) {
		return false
	}
	a, ok := s.admissions[id]
	if !ok || a.Admitter == id {
		return false
	}
	return s.validAt(a.Admitter, a.IssuedAt, visiting)
}

// Lookup returns the admission record for id, if any.
func (s *Set) Lookup(id PublicKey) (Admission, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.admissions[id]
	return a, ok
}

// DHKeyOf returns the DH public key of a valid member.
func (s *Set) DHKeyOf(id PublicKey) (DHKey, error) {
	if !s.Valid(id) {
		return DHKey{}, fmt.Errorf("%s is not a member", id.Short())
	}
	a, ok := s.Lookup(id)
	if !ok {
		return DHKey{}, fmt.Errorf("no admission record for %s", id.Short())
	}
	return a.DHKey, nil
}

// ByName returns the valid member with the given name, if exactly one exists.
func (s *Set) ByName(name string) (Admission, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var found Admission
	n := 0
	for id, a := range s.admissions {
		if a.Name == name && s.valid(id, map[PublicKey]bool{}) {
			found, n = a, n+1
		}
	}
	return found, n == 1
}

// Members lists the valid members' admissions, sorted by name.
func (s *Set) Members() []Admission {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []Admission
	for id, a := range s.admissions {
		if s.valid(id, map[PublicKey]bool{}) {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
