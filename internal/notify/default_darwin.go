//go:build darwin

package notify

// Default is None: launchd has no readiness protocol.
func Default() Notifier { return None{} }
