package edgeerrors

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestErrorMappingKeepsCausesInternal(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		code   Code
		status int
	}{
		{"validation", New(InvalidArgument, errors.New("sensitive details")), InvalidArgument, 400},
		{"authentication", New(Unauthenticated, errors.New("secret-token")), Unauthenticated, 401},
		{"denied", New(PermissionDenied, nil), PermissionDenied, 403},
		{"missing", New(NotFound, nil), NotFound, 404},
		{"duplicate", New(AlreadyExists, nil), AlreadyExists, 409},
		{"precondition", New(FailedPrecondition, nil), FailedPrecondition, 412},
		{"quota", New(ResourceExhausted, nil), ResourceExhausted, 429},
		{"unavailable", New(Unavailable, nil), Unavailable, 503},
		{"deadline", fmt.Errorf("wrap: %w", context.DeadlineExceeded), DeadlineExceeded, 504},
		{"canceled", context.Canceled, Canceled, 408},
		{"unimplemented", New(Unimplemented, nil), Unimplemented, 501},
		{"internal", errors.New("secret-password"), Internal, 500},
		{"unknown code", New(Code("server_debug"), errors.New("secret")), Internal, 500},
		{"nil", nil, Internal, 500},
		{"wrapped", fmt.Errorf("context: %w", New(InvalidArgument, errors.New("secret"))), InvalidArgument, 400},
		{"body too large", fmt.Errorf("wrapped: %w", &http.MaxBytesError{Limit: 100}), ResourceExhausted, 413},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := Map(tc.err)
			if p.Code != tc.code || p.ConnectCode() != string(tc.code) || p.HTTPStatus != tc.status {
				t.Fatalf("mapped %+v, expected %s / %d", p, tc.code, tc.status)
			}
			if strings.Contains(p.Message, "secret") || strings.Contains(p.Message, "debug") {
				t.Fatalf("secret leaked in message: %q", p.Message)
			}
			w := httptest.NewRecorder()
			WriteHTTP(w, tc.err)
			if w.Code != tc.status || w.Header().Get("Cache-Control") != "no-store" ||
				w.Header().Get("Content-Type") != "application/json; charset=utf-8" {
				t.Fatalf("status=%d headers=%+v", w.Code, w.Header())
			}
			var decoded Public
			if err := json.Unmarshal(w.Body.Bytes(), &decoded); err != nil {
				t.Fatal(err)
			}
			if decoded.Code != tc.code || decoded.Message != p.Message || strings.Contains(w.Body.String(), "secret") {
				t.Fatalf("unsafe response: %s", w.Body.String())
			}
		})
	}
}

func TestErrorUnwrapPreservesInternalCause(t *testing.T) {
	underlying := errors.New("private internal reason")
	err := New(Unavailable, underlying)
	if !errors.Is(err, underlying) {
		t.Fatal("internal cause no longer unwraps")
	}
	if !strings.Contains(err.Error(), underlying.Error()) {
		t.Fatal("internal diagnostic lost")
	}
	if strings.Contains(Map(err).Message, "private") {
		t.Fatal("private reason exposed to caller")
	}
}
