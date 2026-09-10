package cli

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_LogLevelFlag_AfterApply(t *testing.T) {
	orig := slog.Default()
	t.Cleanup(func() { slog.SetDefault(orig) })
	ctx := context.Background()

	require.NoError(t, LogLevelFlag("debug").AfterApply())
	assert.True(t, slog.Default().Enabled(ctx, slog.LevelDebug))

	require.NoError(t, LogLevelFlag("ERROR").AfterApply(), "case-insensitive")
	assert.False(t, slog.Default().Enabled(ctx, slog.LevelWarn))
	assert.True(t, slog.Default().Enabled(ctx, slog.LevelError))

	assert.ErrorContains(t, LogLevelFlag("loud").AfterApply(), "could not parse log level")
}
