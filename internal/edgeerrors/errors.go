// Package edgeerrors converts typed internal errors to a small, safe public
// error vocabulary. It has no Connect-Go dependency; CEX 20.3 can translate
// Public.Code to the matching connect.Code without exposing internal causes.
package edgeerrors

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
)

type Code string

const (
	InvalidArgument    Code = "invalid_argument"
	Unauthenticated    Code = "unauthenticated"
	PermissionDenied   Code = "permission_denied"
	NotFound           Code = "not_found"
	AlreadyExists      Code = "already_exists"
	FailedPrecondition Code = "failed_precondition"
	ResourceExhausted  Code = "resource_exhausted"
	Unavailable        Code = "unavailable"
	DeadlineExceeded   Code = "deadline_exceeded"
	Canceled           Code = "canceled"
	Unimplemented      Code = "unimplemented"
	Internal           Code = "internal"
)

// Error retains a cause for internal diagnostics. Only Map/WriteHTTP may be
// used to present failures to clients; errors containing causes are NOT safe.
type Error struct {
	code  Code
	cause error
}

func (e *Error) Error() string {
	if e.cause != nil {
		return string(e.code) + ": " + e.cause.Error()
	}
	return string(e.code)
}
func (e *Error) Unwrap() error { return e.cause }

// New classifies a failure without choosing a client-controlled error message.
func New(code Code, cause error) error { return &Error{code: code, cause: cause} }

// Public contains only allowlisted client-visible information. Message never
// derives from the internal error text or from untrusted request values.
type Public struct {
	Code       Code   `json:"code"`
	Message    string `json:"message"`
	HTTPStatus int    `json:"-"`
}

// ConnectCode returns the semantic Connect code name (e.g. "invalid_argument").
// The eventual Connect adapter must use a typed Connect code, not this string
// as a response header or literal HTTP status mapping.
func (p Public) ConnectCode() string { return string(p.Code) }

func Map(err error) Public {
	if err == nil {
		return public(Internal)
	}
	var maxBytes *http.MaxBytesError
	if errors.As(err, &maxBytes) {
		p := public(ResourceExhausted)
		p.HTTPStatus = http.StatusRequestEntityTooLarge
		return p
	}
	var classified *Error
	if errors.As(err, &classified) {
		return public(classified.code)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return public(DeadlineExceeded)
	}
	if errors.Is(err, context.Canceled) {
		return public(Canceled)
	}
	return public(Internal)
}

func public(code Code) Public {
	switch code {
	case InvalidArgument:
		return Public{code, "invalid request", http.StatusBadRequest}
	case Unauthenticated:
		return Public{code, "authentication required or invalid", http.StatusUnauthorized}
	case PermissionDenied:
		return Public{code, "permission denied", http.StatusForbidden}
	case NotFound:
		return Public{code, "resource not found", http.StatusNotFound}
	case AlreadyExists:
		return Public{code, "resource already exists", http.StatusConflict}
	case FailedPrecondition:
		return Public{code, "request precondition failed", http.StatusPreconditionFailed}
	case ResourceExhausted:
		return Public{code, "resource limit exceeded", http.StatusTooManyRequests}
	case Unavailable:
		return Public{code, "service temporarily unavailable", http.StatusServiceUnavailable}
	case DeadlineExceeded:
		return Public{code, "request deadline exceeded", http.StatusGatewayTimeout}
	case Canceled:
		return Public{code, "request canceled", http.StatusRequestTimeout}
	case Unimplemented:
		return Public{code, "operation not implemented", http.StatusNotImplemented}
	default:
		return Public{Internal, "internal server error", http.StatusInternalServerError}
	}
}

func WriteHTTP(w http.ResponseWriter, err error) {
	p := Map(err)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(p.HTTPStatus)
	// All fields come from constants, but JSON encoding also guarantees a
	// correctly escaped, stable wire format.
	_ = json.NewEncoder(w).Encode(p)
}
