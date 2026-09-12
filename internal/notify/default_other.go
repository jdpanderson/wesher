//go:build !linux && !darwin

package notify

// Default is None. On Windows the service runner hands the agent an SCM
// notifier itself when it runs as a service; started from a console, there
// is no manager to tell.
func Default() Notifier { return None{} }
