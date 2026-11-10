package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testToken = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func validTestKey() keyJSON {
	digest := sha256.Sum256([]byte(testToken))
	return keyJSON{
		TokenSHA256: hex.EncodeToString(digest[:]),
		SubjectID:   "trader-1", AccountID: "account-11",
		Permissions: []Permission{OrdersRead, OrdersWrite},
		ExpiresAt:   time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	}
}

func writeKeyFile(t *testing.T, body []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "credentials.json")
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func encodeFile(t *testing.T, keys ...keyJSON) []byte {
	t.Helper()
	body, err := json.Marshal(keyFile{Version: 1, Keys: keys})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestOpaqueVerifierValidInvalidAndExpiry(t *testing.T) {
	verifier, err := LoadOpaqueVerifier(writeKeyFile(t, encodeFile(t, validTestKey())))
	if err != nil {
		t.Fatal(err)
	}
	principal, err := verifier.Verify(context.Background(), testToken)
	if err != nil || principal.AccountID != "account-11" || principal.SubjectID != "trader-1" ||
		!principal.HasPermission(OrdersRead) || !principal.HasPermission(OrdersWrite) {
		t.Fatalf("principal = %+v, err = %v", principal, err)
	}
	for _, token := range []string{"", "not-a-token", strings.Repeat("a", 64), strings.ToUpper(testToken), testToken + "a", testToken[:63]} {
		if _, err := verifier.Verify(context.Background(), token); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("unexpected credential result for %q: %v", token, err)
		}
	}
	verifier.clock = func() time.Time { return time.Now().Add(8 * 24 * time.Hour) }
	if _, err := verifier.Verify(context.Background(), testToken); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expired token accepted: %v", err)
	}
}

func TestOpaqueVerifierRejectsUnsafeRegistry(t *testing.T) {
	valid := validTestKey()
	tests := []struct {
		name string
		body []byte
	}{
		{"empty", []byte("")},
		{"unknown field", []byte(`{"version":1,"keys":[],"ignore":1}`)},
		{"trailing JSON", append(encodeFile(t, valid), []byte(" {}")...)},
		{"too large", append(encodeFile(t, valid), []byte(strings.Repeat(" ", maxKeyFileBytes))...)},
		{"no keys", encodeFile(t)},
		{"duplicate", encodeFile(t, valid, valid)},
		{"bad SHA", func() []byte { v := valid; v.TokenSHA256 = "not-hex"; return encodeFile(t, v) }()},
		{"unknown permission", func() []byte { v := valid; v.Permissions = []Permission{"admin:*"}; return encodeFile(t, v) }()},
		{"duplicate permission", func() []byte {
			v := valid
			v.Permissions = []Permission{OrdersRead, OrdersRead}
			return encodeFile(t, v)
		}()},
		{"no permissions", func() []byte { v := valid; v.Permissions = nil; return encodeFile(t, v) }()},
		{"bad subject", func() []byte { v := valid; v.SubjectID = "dev\noperator"; return encodeFile(t, v) }()},
		{"bad account", func() []byte { v := valid; v.AccountID = ""; return encodeFile(t, v) }()},
		{"expired", func() []byte {
			v := valid
			v.ExpiresAt = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
			return encodeFile(t, v)
		}()},
		{"too long", func() []byte {
			v := valid
			v.ExpiresAt = time.Now().Add(8 * 24 * time.Hour).UTC().Format(time.RFC3339)
			return encodeFile(t, v)
		}()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if verifier, err := LoadOpaqueVerifier(writeKeyFile(t, tt.body)); err == nil {
				t.Fatalf("accepted unsafe registry: %+v", verifier)
			}
		})
	}
}
