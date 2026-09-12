//go:build !windows

package cluster

import "os"

// replace moves tmp over dst atomically; a reader sees the old file or the
// new one, never a mix.
func replace(tmp, dst string) error { return os.Rename(tmp, dst) }
