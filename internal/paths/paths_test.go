package paths

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_paths_absolute(t *testing.T) {
	for name, p := range map[string]string{"StateDir": StateDir, "ConfigFile": ConfigFile, "RunDir": RunDir, "HostsFile": HostsFile} {
		assert.True(t, filepath.IsAbs(p), "%s = %q", name, p)
	}
	assert.Equal(t, "config.yaml", filepath.Base(ConfigFile))
	assert.Equal(t, "hosts", filepath.Base(HostsFile))
}
