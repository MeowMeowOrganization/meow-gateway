package bootstrap

import (
	"connectrpc.com/connect"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	publicconnect "github.com/MeowMeowOrganization/meow-contracts/gen/go/meow/exchange/api/v1alpha1/apiv1alpha1connect"
	"github.com/MeowMeowOrganization/meow-gateway/internal/auth"
	"github.com/MeowMeowOrganization/meow-gateway/internal/browserauth"
	"github.com/MeowMeowOrganization/meow-gateway/internal/config"
	"github.com/MeowMeowOrganization/meow-gateway/internal/identitypg"
	"github.com/MeowMeowOrganization/meow-gateway/internal/middleware"
	"github.com/MeowMeowOrganization/meow-gateway/internal/oidcclient"
	"github.com/MeowMeowOrganization/meow-gateway/internal/ratelimit"
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
	prune   func(context.Context) error
}

// Dependencies contains test-injectable edge dependencies. A nil Verifier
// defaults to DenyAll; a nil order dependency uses a typed Connect client if
// an upstream URL was configured, otherwise order submissions fail closed.
type Dependencies struct {
	Verifier auth.Verifier
	Orders   gatewayrpc.OrderSubmitter
	Markets  gatewayrpc.MarketReader
	Browser  *browserauth.Handler
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
		if cfg.Auth.CredentialsFile != "" {
			verifier, err := auth.LoadOpaqueVerifier(cfg.Auth.CredentialsFile)
			if err != nil {
				return nil, fmt.Errorf("load auth credentials: %w", err)
			}
			deps.Verifier = verifier
		} else {
			deps.Verifier = auth.DenyAll{}
		}
	}
	var cleanup func()
	var prune func(context.Context) error
	if cfg.Browser.Enabled && deps.Browser == nil {
		store, err := identitypg.Open(context.Background(), cfg.Browser.DatabaseURL)
		if err != nil {
			return nil, fmt.Errorf("open persistent identity store: %w", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		provider, err := oidcclient.New(ctx, cfg.Browser.OIDCIssuer, cfg.Browser.ClientID, cfg.Browser.ClientSecret, cfg.Browser.PublicOrigin+"/auth/callback")
		cancel()
		if err != nil {
			store.Close()
			return nil, fmt.Errorf("OIDC initialization: %w", err)
		}
		deps.Browser, err = browserauth.New(browserauth.Config{PublicOrigin: cfg.Browser.PublicOrigin, Issuer: cfg.Browser.OIDCIssuer, Secure: strings.HasPrefix(cfg.Browser.PublicOrigin, "https://")}, store, provider)
		if err != nil {
			store.Close()
			return nil, fmt.Errorf("browser auth initialization: %w", err)
		}
		cleanup = func() { _ = store.Close() }
		prune = store.Prune
	}
	if deps.Orders == nil && cfg.HTTP.OrderServiceURL != "" {
		client := order.New(cfg.HTTP.OrderServiceURL, cfg.HTTP.OrderServiceTimeout)
		deps.Orders = client
		prior := cleanup
		cleanup = func() {
			client.CloseIdleConnections()
			if prior != nil {
				prior()
			}
		}
	}
	ipLimiter := ratelimit.New(cfg.Auth.IPRequestsPerMinute, time.Minute, 10000)
	accountReadLimiter := ratelimit.New(cfg.Auth.AccountReadsPerMinute, time.Minute, 10000)
	accountWriteLimiter := ratelimit.New(cfg.Auth.AccountWritesPerMinute, time.Minute, 10000)
	procedures := map[string]auth.Permission{
		publicconnect.TradingServiceSubmitLimitOrderProcedure: auth.OrdersWrite,
		publicconnect.TradingServiceCancelOrderProcedure:      auth.OrdersWrite,
		publicconnect.TradingServiceGetOrderProcedure:         auth.OrdersRead,
		publicconnect.TradingServiceGetOpenOrdersProcedure:    auth.OrdersRead,
	}
	srv := server.New(cfg.HTTP.ReadHeaderTimeout, logger,
		middleware.AssignRequestID,
		middleware.AccessLog(logger),
		middleware.RecoverPanic(logger),
		middleware.LimitByPeerIP(ipLimiter),
		middleware.CORS(cfg.HTTP.CORSAllowedOrigins),
		middleware.LimitRequestBody(cfg.HTTP.MaxRequestBodyBytes),
	)
	// Generated handler registration is the only source of public RPC paths.
	tradingPath, tradingHTTP := publicconnect.NewTradingServiceHandler(
		gatewayrpc.NewTradingHandler(deps.Orders),
		connect.WithReadMaxBytes(int(cfg.HTTP.MaxRequestBodyBytes)),
	)
	authorize := auth.Bearer(deps.Verifier)
	if cfg.Browser.Enabled {
		if deps.Browser == nil {
			if cleanup != nil {
				cleanup()
			}
			return nil, errors.New("browser enabled without a browser auth dependency")
		}
		authorize = auth.BearerOrSession(deps.Verifier, deps.Browser)
		srv.Handle("GET /auth/login", http.HandlerFunc(deps.Browser.Login))
		srv.Handle("GET /auth/callback", http.HandlerFunc(deps.Browser.Callback))
		srv.Handle("GET /auth/session", http.HandlerFunc(deps.Browser.Session))
		srv.Handle("POST /auth/logout", http.HandlerFunc(deps.Browser.Logout))
	}
	srv.Handle(tradingPath, authorize(
		auth.RequirePermissions(procedures)(
			middleware.LimitByAccount(accountReadLimiter, accountWriteLimiter, procedures)(tradingHTTP),
		),
	))
	marketPath, marketHTTP := publicconnect.NewMarketServiceHandler(
		gatewayrpc.NewMarketHandler(deps.Markets),
		connect.WithReadMaxBytes(int(cfg.HTTP.MaxRequestBodyBytes)),
	)
	srv.Handle(marketPath, marketHTTP)
	return &App{cfg: cfg, logger: logger, http: srv, cleanup: cleanup, prune: prune}, nil
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
		if a.cleanup != nil {
			a.cleanup()
		}
		return fmt.Errorf("listen on %s: %w", a.cfg.HTTP.Addr, err)
	}
	return a.Serve(ctx, listener)
}

// Serve takes ownership of listener. Accepting an injected listener makes the
// lifecycle testable without hard-coded ports and will also suit future tests.
func (a *App) Serve(ctx context.Context, listener net.Listener) error {
	defer listener.Close()
	if a.prune != nil {
		pruneCtx, stop := context.WithCancel(ctx)
		defer stop()
		go func() {
			ticker := time.NewTicker(10 * time.Minute)
			defer ticker.Stop()
			for {
				select {
				case <-pruneCtx.Done():
					return
				case <-ticker.C:
					taskCtx, cancel := context.WithTimeout(pruneCtx, 5*time.Second)
					err := a.prune(taskCtx)
					cancel()
					if err != nil {
						a.logger.Warn("gateway identity cleanup failed", "error_type", fmt.Sprintf("%T", err))
					}
				}
			}
		}()
	}
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
