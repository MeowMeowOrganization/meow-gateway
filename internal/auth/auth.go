// Package auth defines the trusted account identity boundary. It does not
// issue tokens, implement browser sessions, or accept identity headers.
package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/MeowMeowOrganization/meow-gateway/internal/edgeerrors"
)

// Principal contains identity derived from verified credentials, never from
// X-Account-ID or any other client-supplied identity header.
type Principal struct {
	AccountID   string
	SubjectID   string
	Permissions []Permission
}

func (p Principal) HasPermission(required Permission) bool {
	for _, permission := range p.Permissions {
		if permission == required {
			return true
		}
	}
	return false
}

// Verifier MUST verify credential signature/validity and resolve its account.
// Return ErrInvalidCredentials for invalid credentials; other errors signify
// verification failures and must not be exposed to clients.
type Verifier interface {
	Verify(ctx context.Context, bearerToken string) (Principal, error)
}

var ErrInvalidCredentials = errors.New("invalid credentials")
var ErrCSRF = errors.New("CSRF validation failed")
var ErrInvalidPrincipal = errors.New("invalid verified principal")

type principalKey struct{}

// WithPrincipal must only be called after a trusted Verifier has succeeded.
// The unexported context key prevents clients from injecting a principal via
// an HTTP header or an unrelated context.WithValue call.
func WithPrincipal(ctx context.Context, principal Principal) (context.Context, error) {
	if principal.AccountID == "" || len(principal.AccountID) > 128 {
		return nil, ErrInvalidPrincipal
	}
	for i := 0; i < len(principal.AccountID); i++ {
		c := principal.AccountID[i]
		if c <= ' ' || c > '~' {
			return nil, ErrInvalidPrincipal
		}
	}
	if principal.SubjectID != "" && (len(principal.SubjectID) > 128 || !safeIdentifier(principal.SubjectID)) {
		return nil, ErrInvalidPrincipal
	}
	seen := map[Permission]bool{}
	for _, permission := range principal.Permissions {
		if !validPermission(permission) || seen[permission] {
			return nil, ErrInvalidPrincipal
		}
		seen[permission] = true
	}
	// Defensive copy: a caller must not be able to change grants in context.
	principal.Permissions = append([]Permission(nil), principal.Permissions...)
	return context.WithValue(ctx, principalKey{}, principal), nil
}

func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(Principal)
	return p, ok
}

// Bearer returns opt-in middleware for a protected route. It is deliberately
// NOT globally installed: health and future public market APIs remain public.
// A concrete Verifier is not provided by CEX 20.2.
func Bearer(verifier Verifier) func(http.Handler) http.Handler {
	if verifier == nil {
		panic("auth.Bearer: nil verifier")
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, ok := bearerToken(r.Header.Values("Authorization"))
			if !ok {
				edgeerrors.WriteHTTP(w, edgeerrors.New(edgeerrors.Unauthenticated, ErrInvalidCredentials))
				return
			}
			principal, err := verifier.Verify(r.Context(), token)
			if err != nil {
				if errors.Is(err, ErrInvalidCredentials) {
					edgeerrors.WriteHTTP(w, edgeerrors.New(edgeerrors.Unauthenticated, err))
				} else {
					edgeerrors.WriteHTTP(w, err) // unknown errors map to safe internal
				}
				return
			}
			ctx, err := WithPrincipal(r.Context(), principal)
			if err != nil {
				edgeerrors.WriteHTTP(w, err) // fail closed on an invalid verifier result
				return
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// bearerToken rejects duplicated Authorization headers, ambiguous spacing,
// multiple schemes, token lists and control characters. No token is logged.
func bearerToken(values []string) (string, bool) {
	if len(values) != 1 {
		return "", false
	}
	parts := strings.Split(values[0], " ")
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || len(parts[1]) == 0 || len(parts[1]) > 8192 {
		return "", false
	}
	for i := 0; i < len(parts[1]); i++ {
		if parts[1][i] < '!' || parts[1][i] > '~' || parts[1][i] == ',' {
			return "", false
		}
	}
	return parts[1], true
}

// CookieVerifier is intentionally distinct from Verifier: browser requests
// require cookie/session validation and Origin + CSRF on state-changing calls.
type CookieVerifier interface {
	VerifyRequest(*http.Request) (Principal, error)
}

// BearerOrSession preserves API-key authentication and only falls back to a
// browser session when Authorization is completely absent. An invalid bearer
// NEVER falls back to an existing browser cookie.
func BearerOrSession(verifier Verifier, cookies CookieVerifier) func(http.Handler) http.Handler {
	if verifier == nil || cookies == nil {
		panic("auth.BearerOrSession: nil verifier")
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var principal Principal
			var err error
			if len(r.Header.Values("Authorization")) != 0 {
				token, ok := bearerToken(r.Header.Values("Authorization"))
				if !ok {
					err = ErrInvalidCredentials
				} else {
					principal, err = verifier.Verify(r.Context(), token)
				}
			} else {
				principal, err = cookies.VerifyRequest(r)
			}
			if err != nil {
				switch {
				case errors.Is(err, ErrInvalidCredentials):
					edgeerrors.WriteHTTP(w, edgeerrors.New(edgeerrors.Unauthenticated, err))
				case errors.Is(err, ErrCSRF):
					edgeerrors.WriteHTTP(w, edgeerrors.New(edgeerrors.PermissionDenied, err))
				default:
					edgeerrors.WriteHTTP(w, err)
				}
				return
			}
			ctx, err := WithPrincipal(r.Context(), principal)
			if err != nil {
				edgeerrors.WriteHTTP(w, err)
				return
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
