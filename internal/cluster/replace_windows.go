//go:build windows

package cluster

import (
	"errors"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

// replaceWait is how long replace keeps trying while dst is open elsewhere.
const replaceWait = 2 * time.Second

// replace moves tmp over dst. Windows refuses to replace a file another
// process has open, and `cheesecloth status` reads the state file, so the
// move is retried while the file is busy.
func replace(tmp, dst string) error {
	deadline := time.Now().Add(replaceWait)
	for {
		err := os.Rename(tmp, dst)
		if err == nil || !(errors.Is(err, windows.ERROR_ACCESS_DENIED) || errors.Is(err, windows.ERROR_SHARING_VIOLATION)) || time.Now().After(deadline) {
			return err
		}
		time.Sleep(10 * time.Millisecond)
	}
}
