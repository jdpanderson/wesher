package cluster

import (
	"log/slog"

	"github.com/hashicorp/memberlist"
	"github.com/jdpanderson/wesher/common"
)

// DelegateNode implements the memberlist.Delegate interface.
type delegateNode struct {
	*common.Node
}

var _ memberlist.Delegate = (*delegateNode)(nil)

// NotifyConflict implements the memberlist.Delegate interface.
func (n *delegateNode) NotifyConflict(node, other *memberlist.Node) {
	slog.Error("node name conflict detected", "name", other.Name, "addr", other.Addr)
}

// NodeMeta implements the memberlist.Delegate interface.
// Metadata is provided by the local node settings, encoding is handled
// by the node implementation directly
func (n *delegateNode) NodeMeta(limit int) []byte {
	encoded, err := n.EncodeMeta(limit)
	if err != nil {
		slog.Error("failed to encode local node", "err", err)
		return nil
	}

	return encoded
}

// NotifyMsg implements the memberlist.Delegate interface
func (n *delegateNode) NotifyMsg([]byte) {}

// GetBroadcasts implements the memberlist.Delegate interface
func (n *delegateNode) GetBroadcasts(overhead, limit int) [][]byte { return nil }

// LocalState implements the memberlist.Delegate interface
func (n *delegateNode) LocalState(join bool) []byte { return nil }

// MergeRemoteState implements the memberlist.Delegate interface
func (n *delegateNode) MergeRemoteState(buf []byte, join bool) {}
