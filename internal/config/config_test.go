package config

import (
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"time"
)

func lookupFrom(values map[string]string) func(string) (string, bool) {
	return func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	}
}

func TestLoadDefaults(t *testing.T) {
	got, err := load(lookupFrom(nil))
	if err != nil {
		t.Fatalf("load defaults: %v", err)
	}
	if !reflect.DeepEqual(got, Defaults()) {
		t.Fatalf("got %+v, want %+v", got, Defaults())
	}
}

func TestLoadOverrides(t *testing.T) {
	got, err := load(lookupFrom(map[string]string{
		"GATEWAY_HTTP_ADDR":            "127.0.0.1:9090",
		"GATEWAY_LOG_LEVEL":            "DEBUG",
		"GATEWAY_LOG_FORMAT":           "text",
		"GATEWAY_READ_HEADER_TIMEOUT":  "3s",
		"GATEWAY_SHUTDOWN_TIMEOUT":     "1m",
		"GATEWAY_MAX_REQUEST_BYTES":    "2097152",
		"GATEWAY_CORS_ALLOWED_ORIGINS": "https://app.example.com, http://localhost:5173",
	}))
	if err != nil {
		t.Fatalf("load overrides: %v", err)
	}
	if got.HTTP.Addr != "127.0.0.1:9090" ||
		got.HTTP.ReadHeaderTimeout != 3*time.Second ||
		got.HTTP.ShutdownTimeout != time.Minute ||
		got.Log.Level != slog.LevelDebug ||
		got.Log.Format != LogFormatText ||
		got.HTTP.MaxRequestBodyBytes != 2<<20 ||
		!reflect.DeepEqual(got.HTTP.CORSAllowedOrigins, []string{"https://app.example.com", "http://localhost:5173"}) {
		t.Fatalf("unexpected configuration: %+v", got)
	}
}

func TestLoadRejectsInvalidEnvironment(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		value string
	}{
		{"empty address", "GATEWAY_HTTP_ADDR", ""},
		{"no port", "GATEWAY_HTTP_ADDR", "127.0.0.1"},
		{"bad port", "GATEWAY_HTTP_ADDR", ":abc"},
		{"zero port", "GATEWAY_HTTP_ADDR", ":0"},
		{"port too high", "GATEWAY_HTTP_ADDR", ":65536"},
		{"surrounding whitespace", "GATEWAY_HTTP_ADDR", " :8080 "},
		{"invalid header timeout", "GATEWAY_READ_HEADER_TIMEOUT", "five"},
		{"zero header timeout", "GATEWAY_READ_HEADER_TIMEOUT", "0s"},
		{"negative header timeout", "GATEWAY_READ_HEADER_TIMEOUT", "-1s"},
		{"invalid shutdown timeout", "GATEWAY_SHUTDOWN_TIMEOUT", "infinity"},
		{"zero shutdown timeout", "GATEWAY_SHUTDOWN_TIMEOUT", "0s"},
		{"negative shutdown timeout", "GATEWAY_SHUTDOWN_TIMEOUT", "-10s"},
		{"unknown level", "GATEWAY_LOG_LEVEL", "verbose"},
		{"empty level", "GATEWAY_LOG_LEVEL", ""},
		{"unknown format", "GATEWAY_LOG_FORMAT", "xml"},
		{"empty format", "GATEWAY_LOG_FORMAT", ""},
		{"zero body limit", "GATEWAY_MAX_REQUEST_BYTES", "0"},
		{"negative body limit", "GATEWAY_MAX_REQUEST_BYTES", "-1"},
		{"non-numeric body limit", "GATEWAY_MAX_REQUEST_BYTES", "1MB"},
		{"overflow body limit", "GATEWAY_MAX_REQUEST_BYTES", "9223372036854775808"},
		{"oversized limit", "GATEWAY_MAX_REQUEST_BYTES", "67108865"},
		{"empty CORS override", "GATEWAY_CORS_ALLOWED_ORIGINS", ""},
		{"wildcard origin", "GATEWAY_CORS_ALLOWED_ORIGINS", "*"},
		{"trailing slash", "GATEWAY_CORS_ALLOWED_ORIGINS", "https://example.com/"},
		{"path in origin", "GATEWAY_CORS_ALLOWED_ORIGINS", "https://example.com/path"},
		{"invalid scheme", "GATEWAY_CORS_ALLOWED_ORIGINS", "file://example.com"},
		{"duplicate origin", "GATEWAY_CORS_ALLOWED_ORIGINS", "https://example.com,https://example.com"},
		{"empty origin entry", "GATEWAY_CORS_ALLOWED_ORIGINS", "https://example.com,"},
		{"userinfo", "GATEWAY_CORS_ALLOWED_ORIGINS", "https://user@example.com"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := load(lookupFrom(map[string]string{tc.key: tc.value}))
			if err == nil {
				t.Fatal("expected configuration error")
			}
			if !strings.Contains(err.Error(), tc.key) {
				t.Fatalf("error %q does not identify %s", err, tc.key)
			}
		})
	}
}

func TestValidateManualConfiguration(t *testing.T) {
	cfg := Defaults()
	cfg.Log.Level = slog.Level(7)
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected manually constructed invalid log level to be rejected")
	}
}

func TestIPv6ListenAddress(t *testing.T) {
	cfg, err := load(lookupFrom(map[string]string{"GATEWAY_HTTP_ADDR": "[::1]:8080"}))
	if err != nil {
		t.Fatalf("IPv6 configuration: %v", err)
	}
	if cfg.HTTP.Addr != "[::1]:8080" {
		t.Fatalf("unexpected address %q", cfg.HTTP.Addr)
	}
}

func TestOrderServiceConfig(t *testing.T) {
	cfg, err := load(lookupFrom(map[string]string{
		"GATEWAY_ORDER_SERVICE_URL":     "https://order.internal:8443",
		"GATEWAY_ORDER_SERVICE_TIMEOUT": "3s",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HTTP.OrderServiceURL != "https://order.internal:8443" || cfg.HTTP.OrderServiceTimeout != 3*time.Second {
		t.Fatalf("got %+v", cfg.HTTP)
	}
	for _, bad := range []string{
		"https://user:pass@example.com", "http://127.0.0.1:8000/private", "ftp://example.com", "https://example.com?token=1", "https://example.com/", " http://localhost:8090", "http://", "bad-url",
	} {
		if _, err := load(lookupFrom(map[string]string{"GATEWAY_ORDER_SERVICE_URL": bad})); err == nil {
			t.Errorf("accepted bad URL %q", bad)
		}
	}
	for _, bad := range []string{"not-a-time", "0s", "-1s"} {
		if _, err := load(lookupFrom(map[string]string{"GATEWAY_ORDER_SERVICE_TIMEOUT": bad})); err == nil {
			t.Errorf("accepted timeout %q", bad)
		}
	}
}

func TestAuthConfigLimitsAndPath(t *testing.T) {
	cfg, err := load(lookupFrom(map[string]string{
		"GATEWAY_AUTH_CREDENTIALS_FILE":     "/tmp/gateway-keys.json",
		"GATEWAY_IP_REQUESTS_PER_MINUTE":    "200",
		"GATEWAY_ACCOUNT_READS_PER_MINUTE":  "80",
		"GATEWAY_ACCOUNT_WRITES_PER_MINUTE": "15",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Auth.CredentialsFile != "/tmp/gateway-keys.json" || cfg.Auth.IPRequestsPerMinute != 200 ||
		cfg.Auth.AccountReadsPerMinute != 80 || cfg.Auth.AccountWritesPerMinute != 15 {
		t.Fatalf("unexpected auth config: %+v", cfg.Auth)
	}
	for _, bad := range []struct{ key, value string }{
		{"GATEWAY_AUTH_CREDENTIALS_FILE", "  /tmp/keys.json"},
		{"GATEWAY_IP_REQUESTS_PER_MINUTE", "0"},
		{"GATEWAY_IP_REQUESTS_PER_MINUTE", "100001"},
		{"GATEWAY_ACCOUNT_READS_PER_MINUTE", "-1"},
		{"GATEWAY_ACCOUNT_WRITES_PER_MINUTE", "abc"},
	} {
		if _, err := load(lookupFrom(map[string]string{bad.key: bad.value})); err == nil {
			t.Fatalf("invalid %s=%q accepted", bad.key, bad.value)
		}
	}
}
