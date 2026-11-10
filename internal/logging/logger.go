package logging

import (
	"io"
	"log/slog"

	"github.com/MeowMeowOrganization/meow-gateway/internal/config"
)

// New constructs the process logger. The configuration is validated at startup.
func New(cfg config.LogConfig, output io.Writer) *slog.Logger {
	options := &slog.HandlerOptions{Level: cfg.Level}
	if cfg.Format == config.LogFormatText {
		return slog.New(slog.NewTextHandler(output, options))
	}
	return slog.New(slog.NewJSONHandler(output, options))
}
