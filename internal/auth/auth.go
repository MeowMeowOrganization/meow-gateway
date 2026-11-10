// Package auth defines the trusted account identity boundary. It deliberately
// does not implement a JWT validator, token issuer, or database lookup.
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
type Principal struct{ AccountID string }

// Verifier MUST verify credential signature/validity and resolve its account.
// Return ErrInvalidCredentials for invalid credentials; other errors signify
// verification failures and must not be exposed to clients.
type Verifier interface {
	Verify(ctx context.Context, bearerToken string) (Principal, error)
}

var ErrInvalidCredentials = errors.New("invalid credentials")
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
