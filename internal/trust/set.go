package trust

import (
	"bytes"
	"errors"
	"iter"
	"math"
	"slices"
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

// ErrUntrustedRoot is returned for a self-signed admission of a non-root identity.
var ErrUntrustedRoot = errors.New("self-signed admission is not the pinned root")

// AddAdmission stores a signature-valid record. It reports whether the set
// changed; a record for an identity already present is kept only if newer.
func (s *Set) AddAdmission(a Admission) (bool, error) {
	if err := a.Validate(); err != nil {
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

// AddRevocation stores a signature-valid revocation. Any member may be
// revoked, the root included: it is a peer, not an authority over the others.
func (s *Set) AddRevocation(r Revocation) (bool, error) {
	if err := r.Validate(); err != nil {
		return false, err
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
	slices.SortFunc(rs.Admissions, func(a, b Admission) int { return bytes.Compare(a.Identity[:], b.Identity[:]) })
	slices.SortFunc(rs.Revocations, func(a, b Revocation) int { return bytes.Compare(a.Identity[:], b.Identity[:]) })
	return rs
}

// Valid reports whether id is currently a member: not revoked by itself or by
// a member, and admitted by the root or by an identity that was a member at
// the time it issued the admission. The root needs no admission of its own.
func (s *Set) Valid(id PublicKey) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.valid(id)
}

// valid is Valid with the lock held.
func (s *Set) valid(id PublicKey) bool {
	return s.validAt(id, math.MaxInt64, map[question]bool{})
}

// question is one thing the recursion has already set out to answer: was this
// identity a member at this time. The same identity is asked about at several
// times along one chain, so the time belongs in the key.
type question struct {
	id PublicKey
	at int64
}

// validAdmissions iterates over the valid members' records; callers hold the lock.
func (s *Set) validAdmissions() iter.Seq[Admission] {
	return func(yield func(Admission) bool) {
		for id, a := range s.admissions {
			if s.valid(id) && !yield(a) {
				return
			}
		}
	}
}

// validAt evaluates membership as of unix time at: revocations issued later
// are ignored, so an admission stays valid if its admitter was a member when
// it signed, even if the admitter was revoked afterwards. A member may always
// revoke itself: only the holder of that key can sign such a record, and it
// takes nobody else out.
//
// Asking whether a revoker was a member reaches the identity it revokes again,
// at the earlier time that identity was admitted, so the cycle guard tracks
// the time as well as the identity. A record's time never changes, so the
// questions the recursion can ask are finite and it always ends.
//
// The root differs from the rest only in needing no admitter. It is revoked by
// the same rule, and judging a revocation of the root reaches the root again
// at the earlier time its revoker was admitted, where the revocation does not
// yet apply. Records the root signed while it was a member therefore stay
// valid after it leaves, and the chains that rest on them are unaffected.
func (s *Set) validAt(id PublicKey, at int64, visiting map[question]bool) bool {
	if id == s.root {
		rev, ok := s.revocations[id]
		if !ok || rev.IssuedAt > at {
			return true
		}
		return rev.Revoker != id && !s.validAt(rev.Revoker, rev.IssuedAt, visiting)
	}
	q := question{id, at}
	if visiting[q] {
		return false
	}
	visiting[q] = true
	defer delete(visiting, q)

	if rev, ok := s.revocations[id]; ok && rev.IssuedAt <= at && (rev.Revoker == id || s.validAt(rev.Revoker, rev.IssuedAt, visiting)) {
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

// ByName returns the valid member with the given name, if exactly one exists.
func (s *Set) ByName(name string) (Admission, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var found Admission
	n := 0
	for a := range s.validAdmissions() {
		if a.Name == name {
			found, n = a, n+1
		}
	}
	return found, n == 1
}

// ErrOverlayFull is returned by FreeHost when every slot is taken.
var ErrOverlayFull = errors.New("no free overlay address")

// FreeHost picks the lowest overlay slot in [1, limit] that no admission
// uses. Slots held only by records that are no longer valid (revoked members)
// are reused when nothing else is free.
func (s *Set) FreeHost(limit uint64) (uint64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	taken := map[uint64]bool{}
	validTaken := map[uint64]bool{}
	for id, a := range s.admissions {
		taken[a.Host] = true
		if s.valid(id) {
			validTaken[a.Host] = true
		}
	}
	for _, used := range []map[uint64]bool{taken, validTaken} {
		for h := uint64(1); h <= limit && h != 0; h++ {
			if !used[h] {
				return h, nil
			}
		}
	}
	return 0, ErrOverlayFull
}

// HostConflict reports whether another valid member holds id's overlay slot
// with a stronger claim: an earlier admission, or the same time and a smaller
// identity. Every node evaluates the same records, so all agree on who yields.
func (s *Set) HostConflict(id PublicKey) (Admission, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	mine, ok := s.admissions[id]
	if !ok {
		return Admission{}, false
	}
	for a := range s.validAdmissions() {
		if a.Identity == id || a.Host != mine.Host {
			continue
		}
		if a.IssuedAt < mine.IssuedAt || (a.IssuedAt == mine.IssuedAt && bytes.Compare(a.Identity[:], id[:]) < 0) {
			return a, true
		}
	}
	return Admission{}, false
}

// NameTaken reports whether a valid member other than except has the name.
func (s *Set) NameTaken(name string, except PublicKey) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for a := range s.validAdmissions() {
		if a.Name == name && a.Identity != except {
			return true
		}
	}
	return false
}
