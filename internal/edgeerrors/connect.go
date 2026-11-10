package edgeerrors

import (
	"errors"

	"connectrpc.com/connect"
)

// ToConnect deliberately reconstructs a *new* public error. A downstream
// *connect.Error may contain messages or details that must never reach users.
// Only well-defined semantic codes survive the boundary.
func ToConnect(err error) error {
	if err == nil {
		return nil
	}
	var upstream *connect.Error
	if errors.As(err, &upstream) {
		return toPublicConnect(upstream.Code())
	}
	p := Map(err)
	return toPublicConnect(codeFor(p.Code))
}

func toPublicConnect(code connect.Code) error {
	var c Code
	switch code {
	case connect.CodeInvalidArgument:
		c = InvalidArgument
	case connect.CodeUnauthenticated:
		c = Unauthenticated
	case connect.CodePermissionDenied:
		c = PermissionDenied
	case connect.CodeNotFound:
		c = NotFound
	case connect.CodeAlreadyExists:
		c = AlreadyExists
	case connect.CodeFailedPrecondition:
		c = FailedPrecondition
	case connect.CodeResourceExhausted:
		c = ResourceExhausted
	case connect.CodeUnavailable:
		c = Unavailable
	case connect.CodeDeadlineExceeded:
		c = DeadlineExceeded
	case connect.CodeCanceled:
		c = Canceled
	case connect.CodeUnimplemented:
		c = Unimplemented
	default:
		c = Internal
	}
	p := public(c)
	return connect.NewError(codeFor(p.Code), errors.New(p.Message))
}

func codeFor(code Code) connect.Code {
	switch code {
	case InvalidArgument:
		return connect.CodeInvalidArgument
	case Unauthenticated:
		return connect.CodeUnauthenticated
	case PermissionDenied:
		return connect.CodePermissionDenied
	case NotFound:
		return connect.CodeNotFound
	case AlreadyExists:
		return connect.CodeAlreadyExists
	case FailedPrecondition:
		return connect.CodeFailedPrecondition
	case ResourceExhausted:
		return connect.CodeResourceExhausted
	case Unavailable:
		return connect.CodeUnavailable
	case DeadlineExceeded:
		return connect.CodeDeadlineExceeded
	case Canceled:
		return connect.CodeCanceled
	case Unimplemented:
		return connect.CodeUnimplemented
	default:
		return connect.CodeInternal
	}
}
