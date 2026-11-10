package bootstrap

import (
	"connectrpc.com/connect"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"

	publicconnect "github.com/MeowMeowOrganization/meow-contracts/gen/go/meow/exchange/api/v1alpha1/apiv1alpha1connect"
	"github.com/MeowMeowOrganization/meow-gateway/internal/auth"
	"github.com/MeowMeowOrganization/meow-gateway/internal/config"
	"github.com/MeowMeowOrganization/meow-gateway/internal/middleware"
	"github.com/MeowMeowOrganization/meow-gateway/internal/server"
	gatewayrpc "github.com/MeowMeowOrganization/meow-gateway/internal/transport/connectrpc"
	"github.com/MeowMeowOrganization/meow-gateway/internal/upstream/order"
)

// App owns startup, readiness transitions, and shutdown. It is intended to run
// only once. All dependencies are constructed explicitly at bootstrap time.
type App struct {
	cfg     config.Config
	logger  *slog.Logger
	http    *server.Server
	cleanup func()
}

// Dependencies contains test-injectable edge dependencies. A nil Verifier
// defaults to DenyAll; a nil order dependency uses a typed Connect client if
// an upstream URL was configured, otherwise order submissions fail closed.
type Dependencies struct {
	Verifier auth.Verifier
	Orders   gatewayrpc.OrderSubmitter
	Markets  gatewayrpc.MarketReader
}

func New(cfg config.Config, logger *slog.Logger) (*App, error) {
	return NewWithDependencies(cfg, logger, Dependencies{})
}

func NewWithDependencies(cfg config.Config, logger *slog.Logger, deps Dependencies) (*App, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate gateway configuration: %w", err)
	}
	if logger == nil {
		return nil, errors.New("gateway logger must not be nil")
	}
	if deps.Verifier == nil {
		deps.Verifier = auth.DenyAll{}
	}
	var cleanup func()
	if deps.Orders == nil && cfg.HTTP.OrderServiceURL != "" {
		client := order.New(cfg.HTTP.OrderServiceURL, cfg.HTTP.OrderServiceTimeout)
		deps.Orders = client
		cleanup = client.CloseIdleConnections
	}
	srv := server.New(cfg.HTTP.ReadHeaderTimeout, logger,
		middleware.AssignRequestID,
		middleware.AccessLog(logger),
		middleware.RecoverPanic(logger),
		middleware.CORS(cfg.HTTP.CORSAllowedOrigins),
		middleware.LimitRequestBody(cfg.HTTP.MaxRequestBodyBytes),
	)
	// Generated handler registration is the only source of public RPC paths.
	tradingPath, tradingHTTP := publicconnect.NewTradingServiceHandler(
		gatewayrpc.NewTradingHandler(deps.Orders),
		connect.WithReadMaxBytes(int(cfg.HTTP.MaxRequestBodyBytes)),
	)
	srv.Handle(tradingPath, auth.Bearer(deps.Verifier)(tradingHTTP))
	marketPath, marketHTTP := publicconnect.NewMarketServiceHandler(
		gatewayrpc.NewMarketHandler(deps.Markets),
		connect.WithReadMaxBytes(int(cfg.HTTP.MaxRequestBodyBytes)),
	)
	srv.Handle(marketPath, marketHTTP)
	return &App{cfg: cfg, logger: logger, http: srv, cleanup: cleanup}, nil
}

// Handler exposes the complete production HTTP routing tree to httptest.
func (a *App) Handler() http.Handler { return a.http.Handler() }

// Run binds the configured address synchronously so listen failures are
// returned to the caller, rather than hidden inside a background goroutine.
func (a *App) Run(ctx context.Context) error {
	if ctx.Err() != nil {
		return nil
	}
	listener, err := net.Listen("tcp", a.cfg.HTTP.Addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", a.cfg.HTTP.Addr, err)
	}
	return a.Serve(ctx, listener)
}

// Serve takes ownership of listener. Accepting an injected listener makes the
// lifecycle testable without hard-coded ports and will also suit future tests.
func (a *App) Serve(ctx context.Context, listener net.Listener) error {
	defer listener.Close()
	if a.cleanup != nil {
		defer a.cleanup()
	}
	if ctx.Err() != nil {
		return nil
	}

	serveDone := make(chan error, 1)
	a.http.SetReady(true)
	go func() {
		serveDone <- a.http.Serve(listener)
	}()
	a.logger.Info("gateway HTTP server listening", "address", listener.Addr().String())

	select {
	case err := <-serveDone:
		a.http.SetReady(false)
		if err == nil {
			return errors.New("HTTP server unexpectedly stopped")
		}
		return fmt.Errorf("HTTP server unexpectedly stopped: %w", err)

	case <-ctx.Done():
		a.http.SetReady(false)
		a.logger.Info("gateway shutdown requested")
		// Never derive the shutdown deadline from the canceled signal context.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), a.cfg.HTTP.ShutdownTimeout)
		shutdownErr := a.http.Shutdown(shutdownCtx)
		cancel()
		if shutdownErr != nil {
			// Shutdown does not forcibly interrupt active handlers when its
			// deadline expires. Close terminates the remaining connections.
			if closeErr := a.http.Close(); closeErr != nil {
				a.logger.Error("force-close after shutdown failure", "error", closeErr)
			}
		}

		serveErr := <-serveDone
		if shutdownErr != nil {
			return fmt.Errorf("graceful HTTP shutdown: %w", shutdownErr)
		}
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			return fmt.Errorf("HTTP server failed while shutting down: %w", serveErr)
		}
		a.logger.Info("gateway stopped")
		return nil
	}
}
