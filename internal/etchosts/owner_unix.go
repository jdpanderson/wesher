//go:build unix

package etchosts

import (
	"os"
	"syscall"
)

// keepOwner gives f the owner and group of the file described by info, so
// the rewritten hosts file keeps them.
func keepOwner(f *os.File, info os.FileInfo) error {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	return f.Chown(int(st.Uid), int(st.Gid))
}
