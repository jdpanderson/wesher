//go:build linux

package notify

// Default is systemd, which is a no-op when the agent is not running under it.
func Default() Notifier { return Systemd{} }
