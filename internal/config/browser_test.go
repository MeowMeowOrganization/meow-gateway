package config

import "testing"

func TestBrowserConfigFailsClosed(t *testing.T) {
	cfg := Defaults()
	cfg.Browser = BrowserConfig{Enabled: true, PublicOrigin: "https://exchange.example", OIDCIssuer: "https://id.example/realms/meow", ClientID: "gateway", ClientSecret: "secret", DatabaseURL: "postgres://user:secret@db.example/meow_gateway?sslmode=verify-full"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid browser configuration: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*BrowserConfig)
	}{
		{"incomplete", func(b *BrowserConfig) { b.ClientSecret = "" }},
		{"nonloopback HTTP", func(b *BrowserConfig) { b.PublicOrigin = "http://exchange.example" }},
		{"untrusted issuer", func(b *BrowserConfig) { b.OIDCIssuer = "http://id.example" }},
		{"origin with path", func(b *BrowserConfig) { b.PublicOrigin = "https://exchange.example/path" }},
		{"no db", func(b *BrowserConfig) { b.DatabaseURL = "" }},
		{"bad db protocol", func(b *BrowserConfig) { b.DatabaseURL = "mysql://db.example/schema" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			invalid := cfg
			tc.mutate(&invalid.Browser)
			if err := invalid.Validate(); err == nil {
				t.Fatal("insecure browser config accepted")
			}
		})
	}
	cfg.Browser.PublicOrigin = "http://localhost:8080"
	cfg.Browser.OIDCIssuer = "http://127.0.0.1:9000/realms/meow"
	cfg.Browser.AllowInsecureLoopback = true
	if err := cfg.Validate(); err != nil {
		t.Fatalf("loopback dev rejected: %v", err)
	}
	cfg.Browser.Enabled = false
	if err := cfg.Validate(); err == nil {
		t.Fatal("disabled browser accepted orphaned secrets")
	}
}
