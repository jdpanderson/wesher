//go:build !linux && !darwin && !windows

package wg

import (
	"fmt"
	"runtime"
)

// errUnsupported is returned where no implementation exists for this
// operating system: the agent refuses to start rather than run without a
// network interface.
var errUnsupported = fmt.Errorf("wireguard interfaces are not supported on %s", runtime.GOOS)

func platform(Config) (device, linker, error) { return nil, nil, errUnsupported }

// remove has nothing to remove where no interface can be created.
func remove(string) error { return nil }

func lookup(string) (string, linker, error) { return "", nil, errUnsupported }
