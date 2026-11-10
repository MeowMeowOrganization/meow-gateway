package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type fakeVerifier struct {
	seenToken string
	principal Principal
	err       error
	calls     int
}

func (v *fakeVerifier) Verify(_ context.Context, token string) (Principal, error) {
	v.calls++
	v.seenToken = token
	return v.principal, v.err
}

func TestPrincipalContextCannotBeForgedByHeaders(t *testing.T) {
	ctx := context.Background()
	if _, ok := PrincipalFromContext(ctx); ok {
		t.Fatal("unexpected principal")
	}
	ctx, err := WithPrincipal(ctx, Principal{AccountID: "verified-account"})
	if err != nil {
		t.Fatal(err)
	}
	p, ok := PrincipalFromContext(ctx)
	if !ok || p.AccountID != "verified-account" {
		t.Fatalf("principal: %+v, found %v", p, ok)
	}
	if _, ok := PrincipalFromContext(context.WithValue(context.Background(), "principal", "fake")); ok {
		t.Fatal("external context key forged principal")
	}
	for _, invalid := range []string{"", " ", " bad", "bad ", strings.Repeat("a", 129), "bad\nvalue", "uniçode"} {
		if _, err := WithPrincipal(context.Background(), Principal{AccountID: invalid}); !errors.Is(err, ErrInvalidPrincipal) {
			t.Fatalf("invalid account %q: %v", invalid, err)
		}
	}
}

func TestBearerMiddlewareForwardsOnlyVerifiedIdentity(t *testing.T) {
	verifier := &fakeVerifier{principal: Principal{AccountID: "account-from-verified-token"}}
	h := Bearer(verifier)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, ok := PrincipalFromContext(r.Context())
		if !ok || principal.AccountID != "account-from-verified-token" {
			t.Fatalf("untrusted principal: %+v", principal)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	r := httptest.NewRequest(http.MethodPost, "/rpc", nil)
	r.Header.Set("Authorization", "Bearer opaque-token")
	r.Header.Set("X-Account-ID", "ATTACKER_ACCOUNT")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusNoContent || verifier.calls != 1 || verifier.seenToken != "opaque-token" {
		t.Fatalf("code=%d verifier=%+v", w.Code, verifier)
	}
}

func TestBearerRejectsMalformedCredentialsWithoutCallingVerifier(t *testing.T) {
	verifier := &fakeVerifier{principal: Principal{AccountID: "verified"}}
	h := Bearer(verifier)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("missing credentials should not reach handler")
	}))
	for _, values := range [][]string{
		nil,
		{""},
		{"Basic aaa"},
		{"Bearer"},
		{"Bearer "},
		{"Bearer  abc"},
		{"Bearer\tabc"},
		{"Bearer a,b"},
		{"Bearer abc def"},
		{"Bearer abc", "Bearer def"},
		{"Bearer " + strings.Repeat("x", 8193)},
	} {
		r := httptest.NewRequest(http.MethodPost, "/", nil)
		for _, value := range values {
			r.Header.Add("Authorization", value)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized || strings.Contains(w.Body.String(), "abc") {
			t.Fatalf("values count %d: status %d, body %q", len(values), w.Code, w.Body.String())
		}
	}
	if verifier.calls != 0 {
		t.Fatalf("verifier called %d times", verifier.calls)
	}
}

func TestBearerVerifierErrorAndInvalidIdentityFailClosed(t *testing.T) {
	for _, tc := range []struct {
		name     string
		verifier *fakeVerifier
		status   int
	}{
		{"invalid credential", &fakeVerifier{err: ErrInvalidCredentials}, http.StatusUnauthorized},
		{"wrapped invalid credential", &fakeVerifier{err: errors.Join(errors.New("outer"), ErrInvalidCredentials)}, http.StatusUnauthorized},
		{"unexpected verifier failure", &fakeVerifier{err: errors.New("secret provider failure")}, http.StatusInternalServerError},
		{"invalid principal", &fakeVerifier{principal: Principal{AccountID: ""}}, http.StatusInternalServerError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := Bearer(tc.verifier)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Fatal("unverified request reached handler")
			}))
			r := httptest.NewRequest(http.MethodPost, "/", nil)
			r.Header.Set("Authorization", "BEARER token")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.status || strings.Contains(w.Body.String(), "secret") || tc.verifier.calls != 1 {
				t.Fatalf("status %d body %q calls %d", w.Code, w.Body.String(), tc.verifier.calls)
			}
		})
	}
}

func TestBearerRejectsNilVerifierAtSetup(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("nil verifier accepted")
		}
	}()
	Bearer(nil)
}
