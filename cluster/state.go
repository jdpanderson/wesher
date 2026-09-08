package cluster

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/costela/wesher/common"
)

// State keeps track of information needed to rejoin the cluster
type state struct {
	ClusterKey []byte
	Nodes      []common.Node
}

var statePathTemplate = "/var/lib/wesher/%s.json"

// statePath is where the state for clusterName is persisted.
func statePath(clusterName string) string {
	return fmt.Sprintf(statePathTemplate, clusterName)
}

func (s *state) save(clusterName string) error {
	statePath := statePath(clusterName)
	if err := os.MkdirAll(filepath.Dir(statePath), 0700); err != nil {
		return err
	}

	stateOut, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(statePath, stateOut, 0600)
}

// loadState reads the persisted state for clusterName; missing or unreadable
// state yields an empty state.
// LoadKey returns the cluster key persisted for clusterName.
func LoadKey(clusterName string) ([]byte, error) {
	key := loadState(clusterName).ClusterKey
	if len(key) == 0 {
		return nil, fmt.Errorf("no cluster key stored in %s", statePath(clusterName))
	}
	return key, nil
}

// KnownNodes returns the peers persisted for clusterName with their metadata
// decoded; nodes whose metadata does not decode are skipped.
func KnownNodes(clusterName string) []common.Node {
	nodes := loadState(clusterName).Nodes
	out := make([]common.Node, 0, len(nodes))
	for _, n := range nodes {
		if err := n.DecodeMeta(); err != nil {
			continue
		}
		out = append(out, n)
	}
	return out
}

func loadState(clusterName string) *state {
	statePath := statePath(clusterName)
	content, err := os.ReadFile(statePath)
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Warn("could not open state", "path", statePath, "err", err)
		}
		return &state{}
	}

	s := &state{}
	if err := json.Unmarshal(content, s); err != nil {
		slog.Warn("could not decode state", "path", statePath, "err", err)
		return &state{}
	}
	return s
}
