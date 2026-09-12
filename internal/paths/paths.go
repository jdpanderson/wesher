// Package paths holds the file system locations cheesecloth uses by default
// on each operating system. Every value is set once at start-up, in the
// platform file for the operating system this binary was built for.
package paths

// StateDir is where the agent keeps the state file of each interface.
// ConfigFile is read when it exists. RunDir holds the control sockets.
// HostsFile is the hosts file the agent writes peer names into.
var (
	StateDir   = stateDir()
	ConfigFile = configFile()
	RunDir     = runDir()
	HostsFile  = hostsFile()
)
