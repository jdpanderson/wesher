//go:build !windows

package cli

import (
	"context"

	"github.com/alecthomas/kong"
	"github.com/jdpanderson/cheesecloth/internal/notify"
)

// Execute runs the parsed command. The agent runs until a signal and reports
// to the platform's service manager.
func Execute(_ *CLI, ktx *kong.Context) error {
	return run(ktx, context.Background(), notify.Default())
}
