//go:build darwin

package wg

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// useTempNameDir keeps the interface-name records of a test out of /var/run.
func useTempNameDir(t *testing.T) {
	t.Helper()
	old := nameDir
	nameDir = t.TempDir()
	t.Cleanup(func() { nameDir = old })
}

func Test_tunName_darwin(t *testing.T) {
	assert.Equal(t, "utun", tunName("wgcloth"), "macOS picks the number itself")
}

func Test_published_darwin(t *testing.T) {
	useTempNameDir(t)
	_, err := osNameOf("wgtest0")
	require.Error(t, err, "nothing recorded yet")
	require.NoError(t, unpublished("wgtest0"), "removing a missing record is fine")

	require.NoError(t, published("wgtest0", "utun7"))
	got, err := osNameOf("wgtest0")
	require.NoError(t, err)
	assert.Equal(t, "utun7", got)
	b, err := os.ReadFile(nameFile("wgtest0"))
	require.NoError(t, err)
	assert.Equal(t, "utun7\n", string(b), "the format wg-quick reads")

	require.NoError(t, unpublished("wgtest0"))
	_, err = osNameOf("wgtest0")
	assert.Error(t, err)
}
