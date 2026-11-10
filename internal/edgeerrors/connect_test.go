package edgeerrors

import (
	"context"
	"errors"
	"strings"
	"testing"

	"connectrpc.com/connect"
)

func TestToConnectSanitizesUpstreamErrors(t *testing.T) {
	cases := []struct {
		err  error
		want connect.Code
	}{
		{connect.NewError(connect.CodeNotFound, errors.New("private order and SQL details")), connect.CodeNotFound},
		{connect.NewError(connect.CodePermissionDenied, errors.New("secret account ID")), connect.CodePermissionDenied},
		{connect.NewError(connect.CodeUnavailable, errors.New("internal DNS host")), connect.CodeUnavailable},
		{connect.NewError(connect.CodeUnknown, errors.New("stack trace secret")), connect.CodeInternal},
		{connect.NewError(connect.CodeAborted, errors.New("postgres conflict")), connect.CodeAborted},
		{errors.New("internal panic SQL key"), connect.CodeInternal},
		{New(InvalidArgument, errors.New("user payload secret")), connect.CodeInvalidArgument},
		{context.Canceled, connect.CodeCanceled},
		{context.DeadlineExceeded, connect.CodeDeadlineExceeded},
	}
	for _, tc := range cases {
		e := ToConnect(tc.err)
		if connect.CodeOf(e) != tc.want {
			t.Errorf("code %v, want %v", connect.CodeOf(e), tc.want)
		}
		for _, secret := range []string{"secret", "SQL", "DNS", "panic", "stack trace", "postgres"} {
			if strings.Contains(e.Error(), secret) {
				t.Errorf("leaked %q: %v", secret, e)
			}
		}
	}
	if err := ToConnect(nil); err != nil {
		t.Fatal("nil must stay nil")
	}
}

func TestAbortedPreservesRetryableConflictWithoutLeakingCause(t *testing.T) {
	upstream := connect.NewError(connect.CodeAborted, errors.New("private transaction details"))
	err := ToConnect(upstream)
	if connect.CodeOf(err) != connect.CodeAborted || strings.Contains(err.Error(), "private transaction") {
		t.Fatalf("incorrect aborted mapping: %v", err)
	}
	if got := Map(New(Aborted, upstream)); got.HTTPStatus != 409 {
		t.Fatalf("aborted HTTP mapping: %+v", got)
	}
}
