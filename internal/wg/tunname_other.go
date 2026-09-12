//go:build !darwin

package wg

// tunName is what the tun interface is created as: the agent's name, which
// the operating system keeps.
func tunName(name string) string { return name }

// published records nothing: the interface carries the agent's name already.
func published(string, string) error { return nil }

func unpublished(string) error { return nil }
