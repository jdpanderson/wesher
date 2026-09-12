//go:build windows

package cli

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows/svc/mgr"
)

func (ServiceInstallCmd) Run() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connecting to the service manager (run as administrator): %w", err)
	}
	defer func() { _ = m.Disconnect() }()
	if s, err := m.OpenService(ServiceName); err == nil {
		_ = s.Close()
		return fmt.Errorf("the service %s exists already", ServiceName)
	}
	s, err := m.CreateService(ServiceName, exe, mgr.Config{
		StartType:   mgr.StartAutomatic,
		DisplayName: "cheesecloth mesh agent",
		Description: "Keeps this machine's wireguard interface in step with its cheesecloth mesh.",
	}, "agent")
	if err != nil {
		return fmt.Errorf("creating the service: %w", err)
	}
	defer func() { _ = s.Close() }()
	fmt.Printf("service %s installed; settings come from the config file. Start it with: sc start %s\n", ServiceName, ServiceName)
	return nil
}

func (ServiceUninstallCmd) Run() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connecting to the service manager (run as administrator): %w", err)
	}
	defer func() { _ = m.Disconnect() }()
	s, err := m.OpenService(ServiceName)
	if err != nil {
		return fmt.Errorf("the service %s is not installed", ServiceName)
	}
	defer func() { _ = s.Close() }()
	if err := s.Delete(); err != nil {
		return fmt.Errorf("removing the service: %w", err)
	}
	fmt.Printf("service %s removed\n", ServiceName)
	return nil
}
