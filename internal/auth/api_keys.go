package auth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// OpaqueVerifier authenticates locally provisioned, high-entropy bearer keys.
// The file contains hashes, not usable bearer credentials. Authorization is
// performed separately by RequirePermissions.
type OpaqueVerifier struct {
	keys  map[[sha256.Size]byte]keyEntry
	clock func() time.Time
}

type keyEntry struct {
	principal Principal
	expiresAt time.Time
}

type keyFile struct {
	Version int       `json:"version"`
	Keys    []keyJSON `json:"keys"`
}

type keyJSON struct {
	TokenSHA256 string       `json:"token_sha256"`
	SubjectID   string       `json:"subject_id"`
	AccountID   string       `json:"account_id"`
	Permissions []Permission `json:"permissions"`
	ExpiresAt   string       `json:"expires_at"`
}

const maxKeyFileBytes = 64 << 10
const maxKeyCount = 256

// LoadOpaqueVerifier reads the credential registry once at startup. Rotations
// require a restart; no endpoint can create or edit credentials at runtime.
func LoadOpaqueVerifier(path string) (*OpaqueVerifier, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("auth key file path is empty")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open auth key file: %w", err)
	}
	defer f.Close()
	payload, err := io.ReadAll(io.LimitReader(f, maxKeyFileBytes+1))
	if err != nil || len(payload) > maxKeyFileBytes {
		return nil, errors.New("auth key file exceeds size limit or cannot be read")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var cfg keyFile
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decode auth key file: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, errors.New("auth key file has trailing data or exceeds size limit")
	}
	if cfg.Version != 1 || len(cfg.Keys) == 0 || len(cfg.Keys) > maxKeyCount {
		return nil, errors.New("invalid auth key file version or key count")
	}
	now := time.Now()
	result := &OpaqueVerifier{keys: make(map[[sha256.Size]byte]keyEntry, len(cfg.Keys)), clock: time.Now}
	for _, item := range cfg.Keys {
		if len(item.TokenSHA256) != sha256.Size*2 || strings.ToLower(item.TokenSHA256) != item.TokenSHA256 {
			return nil, errors.New("invalid token SHA-256 encoding")
		}
		decoded, err := hex.DecodeString(item.TokenSHA256)
		if err != nil || hex.EncodeToString(decoded) != item.TokenSHA256 {
			return nil, errors.New("invalid token SHA-256 digest")
		}
		var digest [sha256.Size]byte
		copy(digest[:], decoded)
		if _, duplicate := result.keys[digest]; duplicate {
			return nil, errors.New("duplicate token digest")
		}
		if item.SubjectID == "" || len(item.SubjectID) > 128 || !safeIdentifier(item.SubjectID) {
			return nil, errors.New("invalid subject identifier")
		}
		principal := Principal{SubjectID: item.SubjectID, AccountID: item.AccountID, Permissions: item.Permissions}
		if _, err := WithPrincipal(context.Background(), principal); err != nil {
			return nil, errors.New("invalid principal in auth key file")
		}
		if len(item.Permissions) == 0 {
			return nil, errors.New("credential without any permission")
		}
		expires, err := time.Parse(time.RFC3339, item.ExpiresAt)
		if err != nil || !expires.After(now) || expires.After(now.Add(7*24*time.Hour)) {
			return nil, errors.New("auth key expiration must be in the next seven days")
		}
		result.keys[digest] = keyEntry{principal: principal, expiresAt: expires}
	}
	return result, nil
}

func (v *OpaqueVerifier) Verify(_ context.Context, bearerToken string) (Principal, error) {
	if v == nil || len(bearerToken) != 64 || !lowercaseHex(bearerToken) {
		return Principal{}, ErrInvalidCredentials
	}
	digest := sha256.Sum256([]byte(bearerToken))
	entry, ok := v.keys[digest]
	if !ok || !v.clock().Before(entry.expiresAt) {
		return Principal{}, ErrInvalidCredentials
	}
	return entry.principal, nil
}

func lowercaseHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func safeIdentifier(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] <= ' ' || s[i] > '~' {
			return false
		}
	}
	return true
}
