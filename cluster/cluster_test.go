package cluster

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_computeClusterKey(t *testing.T) {
	provided := []byte("providedproviderprovidedprovided")
	stored := []byte("storedstoredstoredstoredstoredst")

	t.Run("provided key wins", func(t *testing.T) {
		s := &state{ClusterKey: stored}
		got, err := computeClusterKey(s, provided)
		require.NoError(t, err)
		assert.Equal(t, provided, got)
		assert.Equal(t, provided, s.ClusterKey)
	})

	t.Run("stored key used when none provided", func(t *testing.T) {
		s := &state{ClusterKey: stored}
		got, err := computeClusterKey(s, nil)
		require.NoError(t, err)
		assert.Equal(t, stored, got)
	})

	t.Run("key generated when both empty", func(t *testing.T) {
		s := &state{}
		got, err := computeClusterKey(s, nil)
		require.NoError(t, err)
		assert.Len(t, got, KeyLen)
		assert.Equal(t, got, s.ClusterKey)
		assert.NotEqual(t, make([]byte, KeyLen), got)
	})
}
