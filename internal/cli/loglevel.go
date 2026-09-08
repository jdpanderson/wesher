package cli

import (
	"fmt"
	"log/slog"
	"os"
)

// LogLevelFlag is the --log-level flag; parsing it installs the default logger.
type LogLevelFlag string

// AfterApply installs the default slog logger at the requested level.
func (l LogLevelFlag) AfterApply() error {
	var level slog.Level
	if err := level.UnmarshalText([]byte(l)); err != nil {
		return fmt.Errorf("could not parse log level: %w", err)
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))
	return nil
}
