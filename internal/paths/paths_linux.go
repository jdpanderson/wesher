//go:build linux

package paths

func stateDir() string   { return "/var/lib/cheesecloth" }
func configFile() string { return "/etc/cheesecloth/config.yaml" }
func runDir() string     { return "/run/cheesecloth" }
func hostsFile() string  { return "/etc/hosts" }
