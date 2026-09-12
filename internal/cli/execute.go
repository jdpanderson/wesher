package cli

import (
	"context"

	"github.com/alecthomas/kong"
	"github.com/jdpanderson/cheesecloth/internal/notify"
)

// run runs the parsed command with ctx and n bound, for commands whose Run
// takes them: the agent stops when ctx is done and reports to n.
func run(ktx *kong.Context, ctx context.Context, n notify.Notifier) error {
	ktx.BindTo(ctx, (*context.Context)(nil))
	ktx.BindTo(n, (*notify.Notifier)(nil))
	return ktx.Run()
}
