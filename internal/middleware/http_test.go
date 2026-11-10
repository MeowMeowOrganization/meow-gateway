package middleware

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/MeowMeowOrganization/meow-gateway/internal/edgeerrors"
)

func testLogger(output io.Writer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(output, nil))
}

func TestRequestIDIgnoresClientHeaderAndSetsTrustedContext(t *testing.T) {
	seen := make(chan string, 2)
	h := AssignRequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := RequestID(r.Context())
		if !ok {
			t.Error("missing ID in trusted context")
		}
		seen <- id
		if r.Header.Get(RequestIDHeader) != "fake-client-id" {
			t.Fatal("original request header unexpectedly modified")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	var ids []string
	for i := 0; i < 2; i++ {
		r := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		r.Header.Set(RequestIDHeader, "fake-client-id")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusNoContent {
			t.Fatalf("status: %d", w.Code)
		}
		id := w.Header().Get(RequestIDHeader)
		if !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(id) || id == "fake-client-id" {
			t.Fatalf("invalid gateway-owned request id: %q", id)
		}
		if got := <-seen; got != id {
			t.Fatalf("context id %q != response id %q", got, id)
		}
		ids = append(ids, id)
	}
	if ids[0] == ids[1] {
		t.Fatal("IDs reused between requests")
	}
	if _, ok := RequestID(httptest.NewRequest(http.MethodGet, "/", nil).Context()); ok {
		t.Fatal("untrusted context had an ID")
	}
}

func TestCORSAllowedOriginAndPreflight(t *testing.T) {
	hits := 0
	h := CORS([]string{"http://localhost:5173"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("X-Internal-Header", "not-exposed")
		w.WriteHeader(http.StatusAccepted)
	}))
	preflight := httptest.NewRequest(http.MethodOptions, "/rpc", nil)
	preflight.Header.Set("Origin", "http://localhost:5173")
	preflight.Header.Set("Access-Control-Request-Method", "POST")
	preflight.Header.Set("Access-Control-Request-Headers", "authorization, content-type, Connect-Timeout-Ms")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, preflight)
	if w.Code != http.StatusNoContent || hits != 0 {
		t.Fatalf("preflight status=%d handler hits=%d", w.Code, hits)
	}
	if w.Header().Get("Access-Control-Allow-Origin") != "http://localhost:5173" ||
		w.Header().Get("Access-Control-Allow-Headers") != "Authorization, Content-Type, Connect-Timeout-Ms" ||
		w.Header().Get("Access-Control-Allow-Methods") != "GET, HEAD, POST" {
		t.Fatalf("preflight CORS headers: %+v", w.Header())
	}
	if w.Header().Get("Access-Control-Allow-Credentials") != "" {
		t.Fatal("credentialed CORS must not be enabled")
	}
	for _, field := range []string{"Origin", "Access-Control-Request-Method", "Access-Control-Request-Headers"} {
		if !strings.Contains(strings.Join(w.Header().Values("Vary"), ","), field) {
			t.Fatalf("missing Vary: %s", field)
		}
	}

	r := httptest.NewRequest(http.MethodPost, "/rpc", nil)
	r.Header.Set("Origin", "http://localhost:5173")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusAccepted || hits != 1 || w.Header().Get("Access-Control-Expose-Headers") != RequestIDHeader {
		t.Fatalf("actual CORS response: status=%d hits=%d headers=%+v", w.Code, hits, w.Header())
	}
}

func TestCORSDeniesUnsupportedPreflights(t *testing.T) {
	allowed := []string{"https://app.example.com"}
	h := CORS(allowed)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("preflight must not invoke handler")
	}))
	for _, tc := range []struct {
		name    string
		origin  string
		method  string
		headers string
	}{
		{"wrong origin", "https://other.example.com", "POST", "Content-Type"},
		{"null origin", "null", "POST", "Content-Type"},
		{"wrong method", "https://app.example.com", "DELETE", "Content-Type"},
		{"unknown header", "https://app.example.com", "POST", "X-Account-ID"},
		{"duplicate header", "https://app.example.com", "POST", "Authorization,authorization"},
		{"empty requested header", "https://app.example.com", "POST", "Content-Type,"},
		{"control header", "https://app.example.com", "POST", "Content-Type, Weird"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodOptions, "/rpc", nil)
			r.Header.Set("Origin", tc.origin)
			r.Header.Set("Access-Control-Request-Method", tc.method)
			r.Header.Set("Access-Control-Request-Headers", tc.headers)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != http.StatusForbidden || w.Header().Get("Access-Control-Allow-Origin") != "" {
				t.Fatalf("status=%d, headers=%+v", w.Code, w.Header())
			}
		})
	}
}

func TestCORSDoesNotAuthorizeCrossOriginActualRequests(t *testing.T) {
	hits := 0
	h := CORS([]string{"https://app.example.com"})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
	}))
	for _, origin := range []string{"", "https://other.example.com", "null"} {
		r := httptest.NewRequest(http.MethodPost, "/rpc", nil)
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusOK || w.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Fatalf("origin %q incorrectly granted CORS: %+v", origin, w.Header())
		}
		if !strings.Contains(strings.Join(w.Header().Values("Vary"), ","), "Origin") {
			t.Fatalf("no Vary: Origin for %q", origin)
		}
	}
	if hits != 3 {
		t.Fatalf("actual requests passed = %d", hits)
	}
}

func TestLimitRequestBodyKnownAndUnknownLengths(t *testing.T) {
	calls := 0
	h := LimitRequestBody(5)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		body, err := io.ReadAll(r.Body)
		if err != nil {
			edgeerrors.WriteHTTP(w, err)
			return
		}
		_, _ = w.Write(body)
	}))

	r := httptest.NewRequest(http.MethodPost, "/rpc", strings.NewReader("123456"))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusRequestEntityTooLarge || calls != 0 {
		t.Fatalf("known-length oversized request: status=%d calls=%d", w.Code, calls)
	}

	r = httptest.NewRequest(http.MethodPost, "/rpc", strings.NewReader("123456"))
	r.ContentLength = -1
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusRequestEntityTooLarge || calls != 1 {
		t.Fatalf("unknown-length oversized request: status=%d calls=%d", w.Code, calls)
	}

	r = httptest.NewRequest(http.MethodPost, "/rpc", strings.NewReader("12345"))
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK || w.Body.String() != "12345" || calls != 2 {
		t.Fatalf("boundary request: status=%d body=%q calls=%d", w.Code, w.Body.String(), calls)
	}
}

func TestLimitRequestBodyExposesMaxBytesError(t *testing.T) {
	h := LimitRequestBody(2)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := io.ReadAll(r.Body)
		var limitErr *http.MaxBytesError
		if !errors.As(err, &limitErr) || limitErr.Limit != 2 {
			t.Fatalf("expected MaxBytesError, got %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("abcdef"))
	r.ContentLength = -1
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusNoContent {
		t.Fatalf("status=%d", w.Code)
	}
}

func TestRecoverPanicBeforeResponseDoesNotLeakDetails(t *testing.T) {
	var logs bytes.Buffer
	h := Chain(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("SECRET_PANIC_CONTENT")
	}), AssignRequestID, AccessLog(testLogger(&logs)), RecoverPanic(testLogger(&logs)))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/panic?secret=TOKEN", nil))
	if w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), `"code":"internal"`) ||
		strings.Contains(w.Body.String(), "SECRET") {
		t.Fatalf("unsafe recovery response: code=%d body=%q", w.Code, w.Body.String())
	}
	if strings.Contains(logs.String(), "SECRET_PANIC_CONTENT") || strings.Contains(logs.String(), "TOKEN") {
		t.Fatalf("sensitive data leaked into transport logs: %s", logs.String())
	}
	var entries []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatal(err)
		}
		entries = append(entries, record)
	}
	if len(entries) != 2 || entries[1]["status"] != float64(500) {
		t.Fatalf("unexpected recovery logs: %+v", entries)
	}
}

func TestRecoverPanicAfterCommitAbortsRatherThanFakingResponse(t *testing.T) {
	var logs bytes.Buffer
	h := RecoverPanic(testLogger(&logs))(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte("partial"))
		panic("late failure")
	}))
	defer func() {
		recovered := recover()
		if recovered != http.ErrAbortHandler {
			t.Fatalf("expected http.ErrAbortHandler, got %v", recovered)
		}
	}()
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
}

func TestAccessLogDoesNotLogQueriesHeadersOrBodies(t *testing.T) {
	var output bytes.Buffer
	h := Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusCreated)
	}), AssignRequestID, AccessLog(testLogger(&output)))
	r := httptest.NewRequest(http.MethodPost, "/orders?token=VERY_SECRET", strings.NewReader("AMOUNT_SECRET"))
	r.Header.Set("Authorization", "Bearer HEADER_SECRET")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusCreated || w.Header().Get(RequestIDHeader) == "" {
		t.Fatalf("status=%d id=%q", w.Code, w.Header().Get(RequestIDHeader))
	}
	for _, secret := range []string{"VERY_SECRET", "AMOUNT_SECRET", "HEADER_SECRET"} {
		if strings.Contains(output.String(), secret) {
			t.Fatalf("secret %q leaked in log %s", secret, output.String())
		}
	}
	var entry map[string]any
	if err := json.Unmarshal(output.Bytes(), &entry); err != nil {
		t.Fatal(err)
	}
	if entry["status"] != float64(201) || entry["method"] != http.MethodPost || entry["path"] != "/orders" ||
		entry["request_id"] != w.Header().Get(RequestIDHeader) {
		t.Fatalf("unexpected access log: %+v", entry)
	}
}

func TestResponseControllerStillSupportsFlush(t *testing.T) {
	h := Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := http.NewResponseController(w).Flush(); err != nil {
			t.Fatalf("flush failed: %v", err)
		}
		fmt.Fprint(w, "streamed")
	}), AccessLog(testLogger(io.Discard)), RecoverPanic(testLogger(io.Discard)))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/stream", nil))
	if w.Code != http.StatusOK || w.Body.String() != "streamed" {
		t.Fatalf("got %d %s", w.Code, w.Body.String())
	}
}

func TestRecoverPanicAfterFlushAbortsResponse(t *testing.T) {
	h := RecoverPanic(testLogger(io.Discard))(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if err := http.NewResponseController(w).Flush(); err != nil {
			t.Fatal(err)
		}
		panic("late failure after flush")
	}))
	defer func() {
		if got := recover(); got != http.ErrAbortHandler {
			t.Fatalf("expected http.ErrAbortHandler after flush, got %v", got)
		}
	}()
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/stream", nil))
}
