package cli

// ServiceName is what the agent is registered as with the Windows Service
// Control Manager.
const ServiceName = "cheesecloth"

// ServiceCmd registers the agent with the Windows Service Control Manager,
// or removes it. Both need an administrator's console.
type ServiceCmd struct {
	Install   ServiceInstallCmd   `cmd:"" help:"register the agent as a Windows service that starts at boot"`
	Uninstall ServiceUninstallCmd `cmd:"" help:"remove the Windows service; stop it first"`
}

// ServiceInstallCmd registers the service; its settings come from the config file.
type ServiceInstallCmd struct{}

// ServiceUninstallCmd removes the service.
type ServiceUninstallCmd struct{}
