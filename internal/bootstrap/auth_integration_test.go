package bootstrap

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"connectrpc.com/connect"
	publicpb "github.com/MeowMeowOrganization/meow-contracts/gen/go/meow/exchange/api/v1alpha1"
	"github.com/MeowMeowOrganization/meow-contracts/gen/go/meow/exchange/api/v1alpha1/apiv1alpha1connect"
	"github.com/MeowMeowOrganization/meow-contracts/gen/go/meow/exchange/private/order/v1alpha1/orderv1alpha1connect"
	"github.com/MeowMeowOrganization/meow-gateway/internal/config"
)

func TestRealOpaqueKeyAuthenticationAuthorizationAndAccountLimit(t *testing.T) {
	const token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	digest := sha256.Sum256([]byte(token))
	payload, err := json.Marshal(map[string]any{
		"version": 1,
		"keys": []any{map[string]any{
			"token_sha256": hex.EncodeToString(digest[:]),
			"subject_id":   "subject-1",
			"account_id":   "trusted-42",
			"permissions":  []string{"orders:read"},
			"expires_at":   time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	credentialPath := filepath.Join(t.TempDir(), "keys.json")
	if err := os.WriteFile(credentialPath, payload, 0600); err != nil {
		t.Fatal(err)
	}

	backend := &privateOrdersFake{}
	path, handler := orderv1alpha1connect.NewOrderServiceHandler(backend)
	privateMux := http.NewServeMux()
	privateMux.Handle(path, handler)
	upstream := httptest.NewServer(privateMux)
	defer upstream.Close()

	cfg := config.Defaults()
	cfg.Auth.CredentialsFile = credentialPath
	cfg.Auth.AccountReadsPerMinute = 1
	cfg.HTTP.OrderServiceURL = upstream.URL
	app := newRPCTestApp(t, cfg, Dependencies{})
	gateway := httptest.NewServer(app.Handler())
	defer gateway.Close()
	client := apiv1alpha1connect.NewTradingServiceClient(gateway.Client(), gateway.URL)

	noToken := connect.NewRequest(&publicpb.GetOrderRequest{OrderId: "77"})
	if _, err := client.GetOrder(context.Background(), noToken); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("missing credential = %v", err)
	}

	write := connect.NewRequest(validPublicSubmit())
	write.Header().Set("Authorization", "Bearer "+token)
	if _, err := client.SubmitLimitOrder(context.Background(), write); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("read-only credential submitted order: %v", err)
	}

	read := connect.NewRequest(&publicpb.GetOrderRequest{OrderId: "77"})
	read.Header().Set("Authorization", "Bearer "+token)
	read.Header().Set("X-Account-ID", "attacker-account")
	resp, err := client.GetOrder(context.Background(), read)
	if err != nil || resp.Msg.Order.GetOrderId() != "77" {
		t.Fatalf("authorized read failed: %v, %v", resp, err)
	}
	backend.mu.Lock()
	account := backend.getAccount
	backend.mu.Unlock()
	if account != "trusted-42" {
		t.Fatalf("forwarded forged account: %q", account)
	}

	readAgain := connect.NewRequest(&publicpb.GetOrderRequest{OrderId: "77"})
	readAgain.Header().Set("Authorization", "Bearer "+token)
	if _, err := client.GetOrder(context.Background(), readAgain); connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Fatalf("read limit did not trip: %v", err)
	}
}

func TestGatewayDoesNotStartWithMissingCredentialRegistry(t *testing.T) {
	cfg := config.Defaults()
	cfg.Auth.CredentialsFile = filepath.Join(t.TempDir(), "missing.json")
	if _, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil {
		t.Fatal("gateway unexpectedly started without configured credentials")
	}
}
