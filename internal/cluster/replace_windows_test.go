//go:build windows

package cluster

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A file a reader holds open cannot be replaced at once on Windows; replace
// waits for the reader to finish.
func Test_replace_waitsForReader(t *testing.T) {
	dir := t.TempDir()
	dst, tmp := filepath.Join(dir, "a.json"), filepath.Join(dir, "a.json.tmp")
	require.NoError(t, os.WriteFile(dst, []byte("old"), 0o600))
	require.NoError(t, os.WriteFile(tmp, []byte("new"), 0o600))

	reader, err := os.Open(dst)
	require.NoError(t, err)
	go func() {
		time.Sleep(200 * time.Millisecond)
		_ = reader.Close()
	}()
	start := time.Now()
	require.NoError(t, replace(tmp, dst))
	assert.GreaterOrEqual(t, time.Since(start), 150*time.Millisecond, "the move waited for the reader")
	b, err := os.ReadFile(dst)
	require.NoError(t, err)
	assert.Equal(t, "new", string(b))
}
