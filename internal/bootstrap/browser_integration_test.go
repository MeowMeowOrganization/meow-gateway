package bootstrap

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"
	publicpb "github.com/MeowMeowOrganization/meow-contracts/gen/go/meow/exchange/api/v1alpha1"
	"github.com/MeowMeowOrganization/meow-contracts/gen/go/meow/exchange/api/v1alpha1/apiv1alpha1connect"
	"github.com/MeowMeowOrganization/meow-contracts/gen/go/meow/exchange/private/order/v1alpha1/orderv1alpha1connect"
	"github.com/MeowMeowOrganization/meow-gateway/internal/auth"
	"github.com/MeowMeowOrganization/meow-gateway/internal/browserauth"
	"github.com/MeowMeowOrganization/meow-gateway/internal/config"
)

type browserStoreStub struct {
	key     [32]byte
	session browserauth.Session
	revoked bool
}

func (s *browserStoreStub) SaveFlow(context.Context, [32]byte, browserauth.Flow) error { return nil }
func (s *browserStoreStub) TakeFlow(context.Context, [32]byte) (browserauth.Flow, error) {
	return browserauth.Flow{}, browserauth.ErrNotFound
}
func (s *browserStoreStub) ResolveIdentity(context.Context, string, string) (browserauth.Identity, error) {
	return browserauth.Identity{}, browserauth.ErrNotFound
}
func (s *browserStoreStub) CreateSession(context.Context, [32]byte, string, browserauth.Identity, time.Time) error {
	return errors.New("unexpected")
}
func (s *browserStoreStub) LoadSession(_ context.Context, k [32]byte) (browserauth.Session, error) {
	if k != s.key || s.revoked {
		return browserauth.Session{}, browserauth.ErrNotFound
	}
	return s.session, nil
}
func (s *browserStoreStub) RevokeSession(_ context.Context, k [32]byte) error {
	if k != s.key {
		return browserauth.ErrNotFound
	}
	s.revoked = true
	return nil
}

type providerStub struct{}

func (providerStub) LoginURL(string, string, string) string {
	return "https://issuer.example/authorize"
}
func (providerStub) Exchange(context.Context, string, string, string) (string, error) {
	return "", errors.New("unused")
}

func TestBrowserSessionThroughConnectRPCUsesTrustedAccount(t *testing.T) {
	const origin = "http://127.0.0.1:8080"
	token := base64.RawURLEncoding.EncodeToString(make([]byte, 32)) // test-only opaque cookie
	csrf := base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	store := &browserStoreStub{key: sha256.Sum256([]byte(token)), session: browserauth.Session{Principal: auth.Principal{AccountID: "account-from-db", SubjectID: "user-from-db", Permissions: []auth.Permission{auth.OrdersRead}}, CSRFToken: csrf}}
	browser, err := browserauth.New(browserauth.Config{PublicOrigin: origin, Issuer: "https://issuer.example", Secure: false}, store, providerStub{})
	if err != nil {
		t.Fatal(err)
	}
	backend := &privateOrdersFake{}
	path, h := orderv1alpha1connect.NewOrderServiceHandler(backend)
	mux := http.NewServeMux()
	mux.Handle(path, h)
	upstream := httptest.NewServer(mux)
	defer upstream.Close()
	cfg := config.Defaults()
	cfg.HTTP.OrderServiceURL = upstream.URL
	cfg.Browser = config.BrowserConfig{Enabled: true, PublicOrigin: origin, OIDCIssuer: "https://issuer.example", ClientID: "test-client", ClientSecret: "local", DatabaseURL: "postgres://dev:dev@127.0.0.1/meow", AllowInsecureLoopback: true}
	app := newRPCTestApp(t, cfg, Dependencies{Browser: browser})
	gateway := httptest.NewServer(app.Handler())
	defer gateway.Close()
	client := apiv1alpha1connect.NewTradingServiceClient(gateway.Client(), gateway.URL)
	request := func() *connect.Request[publicpb.GetOrderRequest] {
		r := connect.NewRequest(&publicpb.GetOrderRequest{OrderId: "77"})
		r.Header().Set("Cookie", "meow_dev_session="+token)
		r.Header().Set("Origin", origin)
		r.Header().Set("X-CSRF-Token", csrf)
		r.Header().Set("X-Account-ID", "attacker")
		return r
	}
	if _, err := client.GetOrder(context.Background(), request()); err != nil {
		t.Fatalf("valid session: %v", err)
	}
	backend.mu.Lock()
	account := backend.getAccount
	backend.mu.Unlock()
	if account != "account-from-db" {
		t.Fatalf("forged account forwarded: %s", account)
	}
	wrongOrigin := request()
	wrongOrigin.Header().Set("Origin", "https://evil.example")
	if _, err = client.GetOrder(context.Background(), wrongOrigin); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("wrong origin %v", err)
	}
	badCSRF := request()
	badCSRF.Header().Set("X-CSRF-Token", "bad")
	if _, err = client.GetOrder(context.Background(), badCSRF); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("bad CSRF %v", err)
	}
	wrongBearer := request()
	wrongBearer.Header().Set("Authorization", "Bearer invalid-token")
	if _, err = client.GetOrder(context.Background(), wrongBearer); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("bearer fallback %v", err)
	}
	write := connect.NewRequest(validPublicSubmit())
	write.Header().Set("Cookie", "meow_dev_session="+token)
	write.Header().Set("Origin", origin)
	write.Header().Set("X-CSRF-Token", csrf)
	if _, err = client.SubmitLimitOrder(context.Background(), write); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("read-only account wrote order: %v", err)
	}
	store.revoked = true
	if _, err = client.GetOrder(context.Background(), request()); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("revoked session %v", err)
	}
}
