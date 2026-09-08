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

func (s *state) save(clusterName string) error {
	statePath := fmt.Sprintf(statePathTemplate, clusterName)
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
func loadState(clusterName string) *state {
	statePath := fmt.Sprintf(statePathTemplate, clusterName)
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
