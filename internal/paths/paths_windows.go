//go:build windows

package paths

import (
	"os"
	"path/filepath"
)

// Windows keeps service data under %ProgramData% and the hosts file under
// the system directory. The environment names both; the usual locations are
// the fallback when it does not.
func stateDir() string   { return filepath.Join(programData(), "cheesecloth") }
func configFile() string { return filepath.Join(programData(), "cheesecloth", "config.yaml") }
func runDir() string     { return filepath.Join(programData(), "cheesecloth") }
func hostsFile() string {
	return filepath.Join(env("SystemRoot", `C:\Windows`), "System32", "drivers", "etc", "hosts")
}

func programData() string { return env("ProgramData", `C:\ProgramData`) }

func env(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}
