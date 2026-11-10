package config

import (
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config contains configuration that is actively used by the gateway.
type Config struct {
	HTTP HTTPConfig
	Log  LogConfig
}

type HTTPConfig struct {
	Addr                string
	ReadHeaderTimeout   time.Duration
	ShutdownTimeout     time.Duration
	MaxRequestBodyBytes int64
	// OrderServiceURL is optional for the foundation; without it trading
	// fails closed with Unavailable. Set it to enable private RPC forwarding.
	OrderServiceURL     string
	OrderServiceTimeout time.Duration
	// CORSAllowedOrigins is an explicit list of browser origins. No wildcard,
	// implicit credentials, or default cross-origin access is granted.
	CORSAllowedOrigins []string
}

type LogFormat string

const (
	LogFormatJSON             LogFormat = "json"
	LogFormatText             LogFormat = "text"
	maxConfiguredRequestBytes int64     = 64 << 20
)

type LogConfig struct {
	Level  slog.Level
	Format LogFormat
}

func Defaults() Config {
	return Config{
		HTTP: HTTPConfig{
			Addr:                ":8080",
			ReadHeaderTimeout:   5 * time.Second,
			ShutdownTimeout:     15 * time.Second,
			MaxRequestBodyBytes: 1 << 20,
			OrderServiceTimeout: 5 * time.Second,
		},
		Log: LogConfig{
			Level:  slog.LevelInfo,
			Format: LogFormatJSON,
		},
	}
}

// Load reads process environment once at startup and rejects invalid values.
func Load() (Config, error) { return load(os.LookupEnv) }

// load accepts an environment lookup function to keep tests hermetic.
func load(lookup func(string) (string, bool)) (Config, error) {
	cfg := Defaults()
	if value, ok := lookup("GATEWAY_HTTP_ADDR"); ok {
		cfg.HTTP.Addr = value
	}
	if value, ok := lookup("GATEWAY_READ_HEADER_TIMEOUT"); ok {
		duration, err := time.ParseDuration(value)
		if err != nil {
			return Config{}, fmt.Errorf("GATEWAY_READ_HEADER_TIMEOUT: %w", err)
		}
		cfg.HTTP.ReadHeaderTimeout = duration
	}
	if value, ok := lookup("GATEWAY_SHUTDOWN_TIMEOUT"); ok {
		duration, err := time.ParseDuration(value)
		if err != nil {
			return Config{}, fmt.Errorf("GATEWAY_SHUTDOWN_TIMEOUT: %w", err)
		}
		cfg.HTTP.ShutdownTimeout = duration
	}
	if value, ok := lookup("GATEWAY_MAX_REQUEST_BYTES"); ok {
		bytes, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return Config{}, fmt.Errorf("GATEWAY_MAX_REQUEST_BYTES: %w", err)
		}
		cfg.HTTP.MaxRequestBodyBytes = bytes
	}
	if value, ok := lookup("GATEWAY_CORS_ALLOWED_ORIGINS"); ok {
		if value == "" {
			return Config{}, fmt.Errorf("GATEWAY_CORS_ALLOWED_ORIGINS: empty override; omit to disable CORS")
		}
		cfg.HTTP.CORSAllowedOrigins = strings.Split(value, ",")
		for i := range cfg.HTTP.CORSAllowedOrigins {
			cfg.HTTP.CORSAllowedOrigins[i] = strings.TrimSpace(cfg.HTTP.CORSAllowedOrigins[i])
		}
	}
	if value, ok := lookup("GATEWAY_ORDER_SERVICE_URL"); ok {
		cfg.HTTP.OrderServiceURL = value
	}
	if value, ok := lookup("GATEWAY_ORDER_SERVICE_TIMEOUT"); ok {
		valueDuration, err := time.ParseDuration(value)
		if err != nil {
			return Config{}, fmt.Errorf("GATEWAY_ORDER_SERVICE_TIMEOUT: %w", err)
		}
		cfg.HTTP.OrderServiceTimeout = valueDuration
	}
	if value, ok := lookup("GATEWAY_LOG_LEVEL"); ok {
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "debug":
			cfg.Log.Level = slog.LevelDebug
		case "info":
			cfg.Log.Level = slog.LevelInfo
		case "warn":
			cfg.Log.Level = slog.LevelWarn
		case "error":
			cfg.Log.Level = slog.LevelError
		default:
			return Config{}, fmt.Errorf("GATEWAY_LOG_LEVEL: unsupported value %q (want debug, info, warn or error)", value)
		}
	}
	if value, ok := lookup("GATEWAY_LOG_FORMAT"); ok {
		cfg.Log.Format = LogFormat(strings.ToLower(strings.TrimSpace(value)))
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) Validate() error {
	if c.HTTP.Addr == "" || strings.TrimSpace(c.HTTP.Addr) != c.HTTP.Addr {
		return fmt.Errorf("GATEWAY_HTTP_ADDR: must be a non-empty host:port address without surrounding whitespace")
	}
	_, port, err := net.SplitHostPort(c.HTTP.Addr)
	if err != nil {
		return fmt.Errorf("GATEWAY_HTTP_ADDR: invalid host:port address %q: %w", c.HTTP.Addr, err)
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return fmt.Errorf("GATEWAY_HTTP_ADDR: port must be between 1 and 65535")
	}
	if c.HTTP.ReadHeaderTimeout <= 0 {
		return fmt.Errorf("GATEWAY_READ_HEADER_TIMEOUT: must be positive")
	}
	if c.HTTP.ShutdownTimeout <= 0 {
		return fmt.Errorf("GATEWAY_SHUTDOWN_TIMEOUT: must be positive")
	}
	if c.HTTP.MaxRequestBodyBytes <= 0 || c.HTTP.MaxRequestBodyBytes > maxConfiguredRequestBytes {
		return fmt.Errorf("GATEWAY_MAX_REQUEST_BYTES: must be between 1 and %d", maxConfiguredRequestBytes)
	}
	if c.HTTP.OrderServiceTimeout <= 0 {
		return fmt.Errorf("GATEWAY_ORDER_SERVICE_TIMEOUT: must be positive")
	}
	if c.HTTP.OrderServiceURL != "" {
		if err := validateUpstreamURL(c.HTTP.OrderServiceURL); err != nil {
			return fmt.Errorf("GATEWAY_ORDER_SERVICE_URL: %w", err)
		}
	}
	seen := make(map[string]bool, len(c.HTTP.CORSAllowedOrigins))
	for _, origin := range c.HTTP.CORSAllowedOrigins {
		if err := validateOrigin(origin); err != nil {
			return fmt.Errorf("GATEWAY_CORS_ALLOWED_ORIGINS: %w", err)
		}
		if seen[origin] {
			return fmt.Errorf("GATEWAY_CORS_ALLOWED_ORIGINS: duplicate origin %q", origin)
		}
		seen[origin] = true
	}
	switch c.Log.Level {
	case slog.LevelDebug, slog.LevelInfo, slog.LevelWarn, slog.LevelError:
	default:
		return fmt.Errorf("GATEWAY_LOG_LEVEL: unsupported log level %s", c.Log.Level)
	}
	switch c.Log.Format {
	case LogFormatJSON, LogFormatText:
	default:
		return fmt.Errorf("GATEWAY_LOG_FORMAT: unsupported value %q (want json or text)", c.Log.Format)
	}
	return nil
}

// validateOrigin accepts browser origins (scheme + host + optional port) only.
// Exact-string matching is intentional: no wildcard or suffix matching.
func validateOrigin(origin string) error {
	if origin == "" || strings.TrimSpace(origin) != origin {
		return fmt.Errorf("invalid origin %q", origin)
	}
	u, err := url.Parse(origin)
	if err != nil || u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" ||
		u.User != nil || u.Opaque != "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.String() != origin {
		return fmt.Errorf("invalid origin %q (want http(s)://host[:port])", origin)
	}
	return nil
}

// Only HTTP(S) base origins are accepted for the Connect upstream client.
// Disallow credentials, paths, fragments and queries to prevent path confusion.
func validateUpstreamURL(raw string) error {
	if strings.TrimSpace(raw) != raw {
		return fmt.Errorf("invalid service URL")
	}
	u, err := url.Parse(raw)
	if err != nil || u == nil || (u.Scheme != "http" && u.Scheme != "https") ||
		u.Hostname() == "" || u.User != nil || u.Opaque != "" ||
		u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.String() != raw {
		return fmt.Errorf("expected an http(s)://host[:port] base URL without path or credentials")
	}
	return nil
}
