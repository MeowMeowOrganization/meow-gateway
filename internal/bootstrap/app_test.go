package bootstrap

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/MeowMeowOrganization/meow-gateway/internal/config"
	"github.com/MeowMeowOrganization/meow-gateway/internal/edgeerrors"
)

func testApp(t *testing.T, cfg config.Config) *App {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	app, err := New(cfg, logger)
	if err != nil {
		t.Fatal(err)
	}
	return app
}

func TestNewRejectsInvalidConfigurationAndLogger(t *testing.T) {
	cfg := config.Defaults()
	cfg.HTTP.ShutdownTimeout = 0
	if _, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil {
		t.Fatal("expected invalid configuration to be rejected")
	}
	if _, err := New(config.Defaults(), nil); err == nil {
		t.Fatal("expected nil logger to be rejected")
	}
}

func TestRunReportsListenFailure(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	cfg := config.Defaults()
	cfg.HTTP.Addr = listener.Addr().String()
	err = testApp(t, cfg).Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "listen on") {
		t.Fatalf("expected listen error, got %v", err)
	}
}

func TestAppServeGracefullyDrainsRequests(t *testing.T) {
	cfg := config.Defaults()
	app := testApp(t, cfg)

	entered := make(chan struct{})
	release := make(chan struct{})
	app.http.Handle("GET /slow", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(entered)
		<-release
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "completed")
	}))

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	baseURL := "http://" + listener.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runDone := make(chan error, 1)
	go func() { runDone <- app.Serve(ctx, listener) }()
	waitForReady(t, baseURL)

	requestDone := make(chan error, 1)
	go func() {
		client := &http.Client{Timeout: 3 * time.Second}
		response, err := client.Get(baseURL + "/slow")
		if err != nil {
			requestDone <- err
			return
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil {
			requestDone <- err
			return
		}
		if response.StatusCode != http.StatusOK || string(body) != "completed" {
			requestDone <- errors.New("unexpected response from draining handler")
			return
		}
		requestDone <- nil
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		close(release)
		t.Fatal("request did not enter handler")
	}

	cancel()
	deadline := time.After(2 * time.Second)
	for app.http.Ready() {
		select {
		case <-deadline:
			close(release)
			t.Fatal("readiness did not clear")
		case <-time.After(time.Millisecond):
		}
	}
	select {
	case err := <-runDone:
		close(release)
		t.Fatalf("app exited before request completed: %v", err)
	case <-time.After(30 * time.Millisecond):
	}

	close(release)
	if err := <-requestDone; err != nil {
		t.Fatalf("active request failed: %v", err)
	}
	if err := <-runDone; err != nil {
		t.Fatalf("graceful app shutdown: %v", err)
	}
	if app.http.Ready() {
		t.Fatal("readiness still enabled after shutdown")
	}
}

func TestAppShutdownDeadlineForcesConnectionClose(t *testing.T) {
	cfg := config.Defaults()
	cfg.HTTP.ShutdownTimeout = 50 * time.Millisecond
	app := testApp(t, cfg)

	entered := make(chan struct{})
	release := make(chan struct{})
	app.http.Handle("GET /blocked", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(entered)
		<-release // deliberately ignores cancellation to simulate a stuck handler
		w.WriteHeader(http.StatusOK)
	}))

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	baseURL := "http://" + listener.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runDone := make(chan error, 1)
	go func() { runDone <- app.Serve(ctx, listener) }()
	waitForReady(t, baseURL)

	requestDone := make(chan struct{})
	go func() {
		client := &http.Client{Timeout: 3 * time.Second}
		response, err := client.Get(baseURL + "/blocked")
		if err == nil {
			response.Body.Close()
		}
		close(requestDone)
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		close(release)
		t.Fatal("blocked request never started")
	}

	cancel()
	select {
	case err := <-runDone:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("shutdown result = %v, want deadline exceeded", err)
		}
	case <-time.After(2 * time.Second):
		close(release)
		t.Fatal("shutdown did not enforce deadline")
	}
	close(release)
	select {
	case <-requestDone:
	case <-time.After(2 * time.Second):
		t.Fatal("client did not finish after force close")
	}
	if app.http.Ready() {
		t.Fatal("readiness must remain false after failed shutdown")
	}
}

func TestAppServeUnexpectedListenerClose(t *testing.T) {
	app := testApp(t, config.Defaults())
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runDone := make(chan error, 1)
	go func() { runDone <- app.Serve(ctx, listener) }()
	waitForReady(t, "http://"+listener.Addr().String())
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-runDone:
		if err == nil || !strings.Contains(err.Error(), "unexpectedly stopped") {
			t.Fatalf("expected unexpected serve error, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("serve did not notice closed listener")
	}
	if app.http.Ready() {
		t.Fatal("readiness remains true after listener failure")
	}
}

func waitForReady(t *testing.T, url string) {
	t.Helper()
	client := &http.Client{Timeout: 150 * time.Millisecond}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		response, err := client.Get(url + "/readyz")
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("gateway did not become ready")
}

// The real bootstrap stack must wrap the health/router and any future
// registered RPC routes; isolated middleware tests alone don't prove wiring.
func TestBootstrapInstallsHTTPProtections(t *testing.T) {
	cfg := config.Defaults()
	cfg.HTTP.MaxRequestBodyBytes = 4
	cfg.HTTP.CORSAllowedOrigins = []string{"https://app.example.com"}
	app := testApp(t, cfg)
	app.http.Handle("POST /echo", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(r.Body)
		if err != nil {
			edgeerrors.WriteHTTP(w, err)
			return
		}
		_, _ = w.Write(data)
	}))

	preflight := httptest.NewRequest(http.MethodOptions, "/echo", nil)
	preflight.Header.Set("Origin", "https://app.example.com")
	preflight.Header.Set("Access-Control-Request-Method", "POST")
	preflight.Header.Set("Access-Control-Request-Headers", "Authorization, Content-Type")
	w := httptest.NewRecorder()
	app.http.Handler().ServeHTTP(w, preflight)
	if w.Code != http.StatusNoContent || w.Header().Get("Access-Control-Allow-Origin") != "https://app.example.com" {
		t.Fatalf("bootstrapped CORS preflight status %d headers %+v", w.Code, w.Header())
	}

	request := httptest.NewRequest(http.MethodPost, "/echo", strings.NewReader("12345"))
	request.Header.Set("X-Request-ID", "spoofed")
	w = httptest.NewRecorder()
	app.http.Handler().ServeHTTP(w, request)
	if w.Code != http.StatusRequestEntityTooLarge || w.Header().Get("X-Request-ID") == "spoofed" || w.Header().Get("X-Request-ID") == "" {
		t.Fatalf("bootstrapped HTTP protection status=%d headers=%+v", w.Code, w.Header())
	}

	w = httptest.NewRecorder()
	app.http.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if w.Code != http.StatusOK || w.Header().Get("X-Request-ID") == "" {
		t.Fatalf("health middleware status=%d headers=%+v", w.Code, w.Header())
	}
}
