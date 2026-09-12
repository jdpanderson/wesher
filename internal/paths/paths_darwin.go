//go:build darwin

package paths

// macOS keeps daemon state under /var/db and has /var/run but no /run.
func stateDir() string   { return "/var/db/cheesecloth" }
func configFile() string { return "/etc/cheesecloth/config.yaml" }
func runDir() string     { return "/var/run/cheesecloth" }
func hostsFile() string  { return "/etc/hosts" }
