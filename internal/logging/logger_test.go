package logging

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/MeowMeowOrganization/meow-gateway/internal/config"
)

func TestJSONLoggingRespectsConfiguredLevel(t *testing.T) {
	var output bytes.Buffer
	logger := New(config.LogConfig{Level: slog.LevelInfo, Format: config.LogFormatJSON}, &output)
	logger.Debug("filtered")
	logger.Info("server started", "component", "gateway")

	var logLine map[string]any
	if err := json.Unmarshal(output.Bytes(), &logLine); err != nil {
		t.Fatalf("expected one JSON log record: %v; output=%q", err, output.String())
	}
	if logLine["msg"] != "server started" || logLine["component"] != "gateway" || logLine["level"] != "INFO" {
		t.Fatalf("unexpected structured log: %v", logLine)
	}
}
