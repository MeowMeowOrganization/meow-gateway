package server

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/MeowMeowOrganization/meow-gateway/internal/middleware"
)

// Server owns only the HTTP transport and process health endpoints. Future
// Connect-RPC routes can be mounted using Handle before Serve begins.
type Server struct {
	http    *http.Server
	mux     *http.ServeMux
	handler http.Handler
	ready   atomic.Bool
}

func New(readHeaderTimeout time.Duration, logger *slog.Logger, middlewares ...middleware.Middleware) *Server {
	mux := http.NewServeMux()
	s := &Server{mux: mux, handler: middleware.Chain(mux, middlewares...)}
	s.http = &http.Server{
		Handler:           s.handler,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		MaxHeaderBytes:    64 << 10,
		IdleTimeout:       60 * time.Second,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelError),
	}
	mux.HandleFunc("GET /healthz", s.healthz)
	mux.HandleFunc("GET /readyz", s.readyz)
	return s
}

// Handle registers a route. Like http.ServeMux.Handle, it must be called
// before the server starts serving requests.
func (s *Server) Handle(pattern string, handler http.Handler) {
	s.mux.Handle(pattern, handler)
}

// Handler exposes the production router for httptest without opening a port.
func (s *Server) Handler() http.Handler {
	return s.handler
}

func (s *Server) SetReady(ready bool) {
	s.ready.Store(ready)
}

func (s *Server) Ready() bool {
	return s.ready.Load()
}

// Serve blocks until the HTTP listener is closed or another server error occurs.
func (s *Server) Serve(listener net.Listener) error {
	return s.http.Serve(listener)
}

// Shutdown first fails readiness, then waits for active HTTP requests to finish.
func (s *Server) Shutdown(ctx context.Context) error {
	s.SetReady(false)
	return s.http.Shutdown(ctx)
}

// Close forcibly closes active connections when graceful shutdown times out.
func (s *Server) Close() error {
	s.SetReady(false)
	return s.http.Close()
}
