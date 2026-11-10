package auth

import "context"

// DenyAll is the deliberately fail-closed production placeholder until a
// credential verifier is implemented. Tests inject a trusted fake verifier.
// It must never be replaced by a hardcoded "accept any token" implementation.
type DenyAll struct{}

func (DenyAll) Verify(context.Context, string) (Principal, error) {
	return Principal{}, ErrInvalidCredentials
}
