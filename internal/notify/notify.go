// Package notify tells the service manager how the agent is doing: ready,
// a status line, stopping. Default picks the manager of the operating system
// this binary was built for; None is for setups without one.
package notify

// Notifier is one service manager's readiness protocol. Errors are returned
// for the caller to log; they never stop the agent.
type Notifier interface {
	// Ready reports that the service is up, with a status line.
	Ready(status string) error
	// Status replaces the status line the manager shows.
	Status(status string) error
	// Stopping reports that the service has begun shutting down.
	Stopping() error
}

// None is the notifier for no service manager, or one without a readiness
// protocol such as launchd: every call succeeds and does nothing.
type None struct{}

func (None) Ready(string) error  { return nil }
func (None) Status(string) error { return nil }
func (None) Stopping() error     { return nil }
