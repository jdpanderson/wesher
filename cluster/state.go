package cluster

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/jdpanderson/cheesecloth/overlay"
	"github.com/jdpanderson/cheesecloth/trust"
)

// state is what a node persists: its identity seed, the membership it trusts
// and the peers it last saw, so it can restart unattended.
type state struct {
	Seed    []byte           `json:"seed"`
	Root    *trust.PublicKey `json:"root,omitempty"`
	Records trust.Records    `json:"records"`
	Peers   []overlay.Node   `json:"nodes"`
}

var statePathTemplate = "/var/lib/cheesecloth/%s.json"

// statePath is where the state for clusterName is persisted.
func statePath(clusterName string) string {
	return fmt.Sprintf(statePathTemplate, clusterName)
}

// save writes the state atomically: a reader (the status command, or a
// restart after a crash mid-write) sees the old file or the new one, never a
// truncated one.
func (s *state) save(clusterName string) error {
	statePath := statePath(clusterName)
	if err := os.MkdirAll(filepath.Dir(statePath), 0700); err != nil {
		return err
	}

	stateOut, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}

	tmp, err := os.CreateTemp(filepath.Dir(statePath), filepath.Base(statePath)+".*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }() // gone already once renamed
	if _, err = tmp.Write(stateOut); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), statePath) // CreateTemp made it 0600
}

// loadState reads the persisted state for clusterName. A missing file is an
// empty state; a file that cannot be read or decoded is an error, so that a
// damaged state is never mistaken for a node that has not started before.
func loadState(clusterName string) (*state, error) {
	statePath := statePath(clusterName)
	content, err := os.ReadFile(statePath)
	if os.IsNotExist(err) {
		return &state{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading state %s: %w", statePath, err)
	}
	s := &state{}
	if err := json.Unmarshal(content, s); err != nil {
		return nil, fmt.Errorf("decoding state %s: %w", statePath, err)
	}
	return s, nil
}

// KnownNodes returns the peers persisted for clusterName with their metadata
// decoded; nodes whose metadata does not decode are skipped, and an unusable
// state file yields none.
func KnownNodes(clusterName string) []overlay.Node {
	st, err := loadState(clusterName)
	if err != nil {
		slog.Warn("could not load cluster state", "err", err)
		return nil
	}
	out := make([]overlay.Node, 0, len(st.Peers))
	for _, n := range st.Peers {
		if err := n.DecodeMeta(); err != nil {
			continue
		}
		out = append(out, n)
	}
	return out
}

// LocalIdentity returns the identity persisted for clusterName, if any.
func LocalIdentity(clusterName string) (trust.PublicKey, bool) {
	st, err := loadState(clusterName)
	if err != nil || len(st.Seed) == 0 {
		return trust.PublicKey{}, false
	}
	id, err := trust.IdentityFromSeed(st.Seed)
	if err != nil {
		return trust.PublicKey{}, false
	}
	return id.Public(), true
}

// Bootstrap is the persisted knowledge a node starts from. Load fills it; the
// agent then either makes the node a root, enrols it, or finds it already
// enrolled, and hands it to New, which keeps it up to date and saves it.
type Bootstrap struct {
	Identity *trust.Identity
	Root     trust.PublicKey // zero until enrolled or initialised
	Records  trust.Records
	Peers    []overlay.Node // last known peers, with metadata
}

// Load reads the state for name, or starts fresh when init is set, and makes
// sure the node has an identity. The identity is persisted immediately.
func Load(name string, init bool) (*Bootstrap, error) {
	st := &state{}
	if !init {
		var err error
		if st, err = loadState(name); err != nil {
			return nil, err
		}
	}
	if len(st.Seed) == 0 {
		id, err := trust.NewIdentity()
		if err != nil {
			return nil, err
		}
		st = &state{Seed: id.Seed()}
		if err := st.save(name); err != nil {
			return nil, fmt.Errorf("saving new identity: %w", err)
		}
		slog.Info("generated node identity", "identity", id.Public().Short(), "path", statePath(name))
	}
	id, err := trust.IdentityFromSeed(st.Seed)
	if err != nil {
		return nil, fmt.Errorf("loading identity from %s: %w", statePath(name), err)
	}
	b := &Bootstrap{Identity: id, Records: st.Records, Peers: st.Peers}
	if st.Root != nil {
		b.Root = *st.Root
	}
	return b, nil
}

// Enrolled reports whether the node already belongs to a cluster: it knows a root.
func (b *Bootstrap) Enrolled() bool { return b.Root != (trust.PublicKey{}) }

// save persists the bootstrap as the state for name.
func (b *Bootstrap) save(name string) error {
	st := &state{Seed: b.Identity.Seed(), Records: b.Records, Peers: b.Peers}
	if b.Enrolled() {
		root := b.Root
		st.Root = &root
	}
	return st.save(name)
}

// Host is the overlay slot this node's admission assigns it.
func (b *Bootstrap) Host() (uint64, error) {
	for _, a := range b.Records.Admissions {
		if a.Identity == b.Identity.Public() {
			return a.Host, nil
		}
	}
	return 0, fmt.Errorf("no admission record for this node (%s)", b.Identity.Public().Short())
}

// InitRoot makes this node the root of a new cluster.
func (b *Bootstrap) InitRoot(nodeName string) {
	b.Root = b.Identity.Public()
	adm := trust.SelfAdmit(b.Identity, nodeName, time.Now())
	b.Records = trust.Records{Admissions: []trust.Admission{adm}}
	b.Peers = nil
}

// Enrol records the outcome of an enrolment exchange.
func (b *Bootstrap) Enrol(root trust.PublicKey, records trust.Records) {
	b.Root = root
	b.Records = records
	b.Peers = nil
}
