package cli

import (
	"fmt"
	"log/slog"
	"os"
)

// LogLevelFlag is the --log-level flag; parsing it installs the default logger.
type LogLevelFlag string

// Level is the flag as a slog level.
func (l LogLevelFlag) Level() (slog.Level, error) {
	var level slog.Level
	if err := level.UnmarshalText([]byte(l)); err != nil {
		return 0, fmt.Errorf("could not parse log level: %w", err)
	}
	return level, nil
}

// AfterApply installs the default slog logger at the requested level.
func (l LogLevelFlag) AfterApply() error {
	level, err := l.Level()
	if err != nil {
		return err
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))
	return nil
}
