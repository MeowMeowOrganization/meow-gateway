package server

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newTestServer() *Server {
	return New(time.Second, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func TestHealthAndReadinessLifecycle(t *testing.T) {
	s := newTestServer()
	tests := []struct {
		name   string
		path   string
		status int
		body   string
	}{
		{"alive before ready", "/healthz", http.StatusOK, `{"status":"ok"}` + "\n"},
		{"not ready initially", "/readyz", http.StatusServiceUnavailable, `{"status":"not_ready"}` + "\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assertResponse(t, s.Handler(), http.MethodGet, tc.path, tc.status, tc.body)
		})
	}

	s.SetReady(true)
	if !s.Ready() {
		t.Fatal("expected ready state")
	}
	assertResponse(t, s.Handler(), http.MethodGet, "/readyz", http.StatusOK, `{"status":"ready"}`+"\n")
	assertResponse(t, s.Handler(), http.MethodGet, "/healthz", http.StatusOK, `{"status":"ok"}`+"\n")

	s.SetReady(false)
	assertResponse(t, s.Handler(), http.MethodGet, "/readyz", http.StatusServiceUnavailable, `{"status":"not_ready"}`+"\n")
	assertResponse(t, s.Handler(), http.MethodGet, "/healthz", http.StatusOK, `{"status":"ok"}`+"\n")
}

func TestHealthRoutesAreMethodRestricted(t *testing.T) {
	s := newTestServer()
	assertResponse(t, s.Handler(), http.MethodPost, "/healthz", http.StatusMethodNotAllowed, "Method Not Allowed\n")
	assertResponse(t, s.Handler(), http.MethodGet, "/unknown", http.StatusNotFound, "404 page not found\n")

	head := httptest.NewRecorder()
	s.Handler().ServeHTTP(head, httptest.NewRequest(http.MethodHead, "/healthz", nil))
	if head.Code != http.StatusOK {
		t.Fatalf("HEAD /healthz: got %d", head.Code)
	}
}

func assertResponse(t *testing.T, handler http.Handler, method, path string, status int, body string) {
	t.Helper()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(method, path, nil))
	if response.Code != status {
		t.Fatalf("%s %s: status %d, want %d", method, path, response.Code, status)
	}
	if actual := response.Body.String(); actual != body {
		t.Fatalf("%s %s: body %q, want %q", method, path, actual, body)
	}
	if status == http.StatusOK || status == http.StatusServiceUnavailable {
		if got := response.Header().Get("Cache-Control"); got != "no-store" {
			t.Fatalf("Cache-Control %q", got)
		}
		if got := response.Header().Get("Content-Type"); got != "application/json; charset=utf-8" {
			t.Fatalf("Content-Type %q", got)
		}
	}
}
