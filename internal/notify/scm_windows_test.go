//go:build windows

package notify

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows/svc"
)

func Test_SCM(t *testing.T) {
	changes := make(chan svc.Status, 4)
	var n Notifier = SCM{Changes: changes}
	require.NoError(t, n.Ready("2 peers"))
	assert.Equal(t, svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}, <-changes)
	require.NoError(t, n.Status("3 peers"))
	assert.Empty(t, changes, "the manager has no status text")
	require.NoError(t, n.Stopping())
	assert.Equal(t, svc.Status{State: svc.StopPending}, <-changes)
}
