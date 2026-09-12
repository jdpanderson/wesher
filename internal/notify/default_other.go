//go:build !linux && !darwin

package notify

// Default is None where no service manager integration exists yet.
func Default() Notifier { return None{} }
