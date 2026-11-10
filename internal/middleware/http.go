// Package middleware contains transport-only HTTP protections. This file has
// no Connect-RPC dependency; Connect interceptors will be added in CEX 20.3.
package middleware

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/MeowMeowOrganization/meow-gateway/internal/edgeerrors"
)

type Middleware func(http.Handler) http.Handler

type requestIDKey struct{}

const RequestIDHeader = "X-Request-ID"

func RequestID(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(requestIDKey{}).(string)
	return id, ok
}

// Chain composes middleware in execution order: the first middleware is
// outermost and runs first on ingress and last on egress.
func Chain(next http.Handler, middlewares ...Middleware) http.Handler {
	for i := len(middlewares) - 1; i >= 0; i-- {
		next = middlewares[i](next)
	}
	return next
}

// AssignRequestID always generates a fresh, gateway-owned 128-bit random ID.
// Incoming client IDs are ignored, preventing header spoofing/log correlation
// confusion. A cryptographic randomness failure fails closed.
func AssignRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var random [16]byte
		if _, err := io.ReadFull(rand.Reader, random[:]); err != nil {
			edgeerrors.WriteHTTP(w, edgeerrors.New(edgeerrors.Internal, err))
			return
		}
		id := hex.EncodeToString(random[:])
		w.Header().Set(RequestIDHeader, id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey{}, id)))
	})
}

// AccessLog records only request transport metadata, never query strings,
// tokens, request bodies, or financial payloads.
func AccessLog(logger *slog.Logger) Middleware {
	if logger == nil {
		panic("middleware.AccessLog: nil logger")
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			tracked := &statusWriter{ResponseWriter: w}
			defer func() {
				status := tracked.status
				if status == 0 {
					status = http.StatusOK
				}
				id, _ := RequestID(r.Context())
				path := r.URL.Path
				if len(path) > 256 {
					path = path[:256]
				}
				logger.Info("http request", "method", r.Method, "path", path,
					"status", status, "duration_ms", time.Since(start).Milliseconds(), "request_id", id)
			}()
			next.ServeHTTP(tracked, r)
		})
	}
}

// RecoverPanic returns a generic HTTP 500 before any response has been written.
// Once headers/body are committed, it aborts the HTTP request instead of
// appending misleading JSON to a potentially successful/streaming response.
func RecoverPanic(logger *slog.Logger) Middleware {
	if logger == nil {
		panic("middleware.RecoverPanic: nil logger")
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tracked := &statusWriter{ResponseWriter: w}
			defer func() {
				if recovered := recover(); recovered != nil {
					if recovered == http.ErrAbortHandler {
						panic(recovered)
					}
					id, _ := RequestID(r.Context())
					logger.Error("HTTP handler panicked", "panic_type", fmt.Sprintf("%T", recovered), "request_id", id)
					if tracked.wroteHeader {
						panic(http.ErrAbortHandler)
					}
					edgeerrors.WriteHTTP(tracked, errors.New("handler panic"))
				}
			}()
			next.ServeHTTP(tracked, r)
		})
	}
}

// LimitRequestBody rejects known over-limit requests before invoking handlers.
// Unknown-length / chunked bodies are bounded by MaxBytesReader; consumers
// must propagate *http.MaxBytesError so the RPC adapter can emit 413 safely.
// The middleware never reads or buffers a body itself (streaming remains safe).
func LimitRequestBody(limit int64) Middleware {
	if limit <= 0 {
		panic("middleware.LimitRequestBody: nonpositive limit")
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ContentLength > limit {
				edgeerrors.WriteHTTP(w, &http.MaxBytesError{Limit: limit})
				return
			}
			if r.Body != nil {
				r.Body = http.MaxBytesReader(w, r.Body, limit)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// CORS only grants browser origins in the configured exact allowlist. It does
// not grant credentialed cookie access or serve as authentication/CSRF control.
// Disallowed preflights return 403; for actual requests no CORS response
// headers are added (the browser enforces access to the response).
func CORS(allowedOrigins []string) Middleware {
	allow := make(map[string]struct{}, len(allowedOrigins))
	for _, origin := range allowedOrigins {
		allow[origin] = struct{}{}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Even responses without Origin must declare Vary for shared
			// caches to distinguish later cross-origin requests.
			w.Header().Add("Vary", "Origin")
			origins := r.Header.Values("Origin")
			if len(origins) == 0 {
				next.ServeHTTP(w, r)
				return
			}
			origin := ""
			if len(origins) == 1 {
				origin = origins[0]
			}
			_, allowed := allow[origin]
			preflight := r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != ""
			if preflight {
				w.Header().Add("Vary", "Access-Control-Request-Method")
				w.Header().Add("Vary", "Access-Control-Request-Headers")
				if !allowed || len(r.Header.Values("Access-Control-Request-Method")) != 1 ||
					len(r.Header.Values("Access-Control-Request-Headers")) > 1 ||
					!allowedMethod(r.Header.Get("Access-Control-Request-Method")) {
					edgeerrors.WriteHTTP(w, edgeerrors.New(edgeerrors.PermissionDenied, nil))
					return
				}
				headers, ok := allowedHeaders(r.Header.Get("Access-Control-Request-Headers"))
				if !ok {
					edgeerrors.WriteHTTP(w, edgeerrors.New(edgeerrors.PermissionDenied, nil))
					return
				}
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Methods", "GET, HEAD, POST")
				if headers != "" {
					w.Header().Set("Access-Control-Allow-Headers", headers)
				}
				w.Header().Set("Access-Control-Max-Age", "600")
				w.WriteHeader(http.StatusNoContent)
				return
			}
			if allowed {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Expose-Headers", RequestIDHeader)
			}
			next.ServeHTTP(w, r)
		})
	}
}

func allowedMethod(method string) bool {
	return method == http.MethodGet || method == http.MethodHead || method == http.MethodPost
}

var corsHeaders = map[string]string{
	"authorization":            "Authorization",
	"content-type":             "Content-Type",
	"connect-protocol-version": "Connect-Protocol-Version",
	"connect-timeout-ms":       "Connect-Timeout-Ms",
	"grpc-timeout":             "Grpc-Timeout",
	"x-grpc-web":               "X-Grpc-Web",
	"x-user-agent":             "X-User-Agent",
	"x-request-id":             "X-Request-ID",
}

func allowedHeaders(headerLine string) (string, bool) {
	if headerLine == "" {
		return "", true
	}
	parts := strings.Split(headerLine, ",")
	if len(parts) > len(corsHeaders) {
		return "", false
	}
	result := make([]string, 0, len(parts))
	seen := make(map[string]bool, len(parts))
	for _, part := range parts {
		key := strings.ToLower(strings.TrimSpace(part))
		canonical, ok := corsHeaders[key]
		if !ok || seen[key] {
			return "", false
		}
		seen[key] = true
		result = append(result, canonical)
	}
	return strings.Join(result, ", "), true
}

// statusWriter tracks response status without losing net/http ResponseController
// support: Unwrap allows flushing, deadlines, and hijacking when supported by
// the underlying writer. It does not buffer responses.
type statusWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (w *statusWriter) WriteHeader(status int) {
	if !w.wroteHeader {
		w.wroteHeader = true
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}
func (w *statusWriter) Write(body []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(body)
}

// FlushError preserves http.ResponseController flushing and records that the
// response is committed. Recovery must abort if a panic follows a flush.
func (w *statusWriter) FlushError() error {
	if err := http.NewResponseController(w.ResponseWriter).Flush(); err != nil {
		return err
	}
	if !w.wroteHeader {
		w.wroteHeader = true
		w.status = http.StatusOK
	}
	return nil
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
