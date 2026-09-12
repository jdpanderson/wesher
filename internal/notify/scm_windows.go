//go:build windows

package notify

import "golang.org/x/sys/windows/svc"

// SCM reports to the Windows Service Control Manager, through the status
// channel svc.Run hands the service. The manager has no status text, so
// Status has nothing to say.
type SCM struct {
	Changes chan<- svc.Status
}

func (s SCM) Ready(string) error {
	s.Changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	return nil
}

func (SCM) Status(string) error { return nil }

func (s SCM) Stopping() error {
	s.Changes <- svc.Status{State: svc.StopPending}
	return nil
}
