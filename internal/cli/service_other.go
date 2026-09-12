//go:build !windows

package cli

import (
	"errors"
	"runtime"
)

var errNoServiceManager = errors.New("the service subcommands register the agent with the Windows Service Control Manager; on " +
	runtime.GOOS + " use the unit or job under dist/")

func (ServiceInstallCmd) Run() error   { return errNoServiceManager }
func (ServiceUninstallCmd) Run() error { return errNoServiceManager }
