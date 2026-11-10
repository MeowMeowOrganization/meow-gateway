package bootstrap

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"connectrpc.com/connect"
	publicpb "github.com/MeowMeowOrganization/meow-contracts/gen/go/meow/exchange/api/v1alpha1"
	"github.com/MeowMeowOrganization/meow-contracts/gen/go/meow/exchange/api/v1alpha1/apiv1alpha1connect"
	marketpb "github.com/MeowMeowOrganization/meow-contracts/gen/go/meow/exchange/market/v1alpha1"
	orderpb "github.com/MeowMeowOrganization/meow-contracts/gen/go/meow/exchange/order/v1alpha1"
	privatepb "github.com/MeowMeowOrganization/meow-contracts/gen/go/meow/exchange/private/order/v1alpha1"
	"github.com/MeowMeowOrganization/meow-contracts/gen/go/meow/exchange/private/order/v1alpha1/orderv1alpha1connect"
	"github.com/MeowMeowOrganization/meow-gateway/internal/auth"
	"github.com/MeowMeowOrganization/meow-gateway/internal/config"
)

type verifierFake struct{}

func (verifierFake) Verify(_ context.Context, token string) (auth.Principal, error) {
	if token == "valid-token" {
		return auth.Principal{AccountID: "trusted-42"}, nil
	}
	return auth.Principal{}, auth.ErrInvalidCredentials
}

type privateOrdersFake struct {
	orderv1alpha1connect.UnimplementedOrderServiceHandler
	mu            sync.Mutex
	account       string
	requestID     string
	authorization string
	calls         int
	cancelAccount string
	getAccount    string
	listAccount   string
	listMarket    string
	listPageSize  int32
	listPageToken string
}

func (f *privateOrdersFake) SubmitLimitOrder(ctx context.Context, req *connect.Request[privatepb.SubmitLimitOrderRequest]) (*connect.Response[privatepb.SubmitLimitOrderResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.account = req.Msg.GetAccountId()
	f.requestID = req.Header().Get("X-Request-ID")
	f.authorization = req.Header().Get("Authorization")
	return connect.NewResponse(&privatepb.SubmitLimitOrderResponse{Order: &orderpb.LimitOrder{OrderId: "77", Status: orderpb.OrderStatus_ORDER_STATUS_OPEN}}), nil
}

func (f *privateOrdersFake) CancelOrder(_ context.Context, req *connect.Request[privatepb.CancelOrderRequest]) (*connect.Response[privatepb.CancelOrderResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cancelAccount = req.Msg.GetAccountId()
	return connect.NewResponse(&privatepb.CancelOrderResponse{
		OrderId: req.Msg.GetOrderId(),
		Status:  privatepb.CancelRequestStatus_CANCEL_REQUEST_STATUS_PENDING,
	}), nil
}

func (f *privateOrdersFake) GetOrder(_ context.Context, req *connect.Request[privatepb.GetOrderRequest]) (*connect.Response[privatepb.GetOrderResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.getAccount = req.Msg.GetAccountId()
	return connect.NewResponse(&privatepb.GetOrderResponse{Order: &privatepb.PrivateOrder{
		OrderId: req.Msg.GetOrderId(), AccountId: req.Msg.GetAccountId(), MarketId: "BTC-USDT",
		Status: privatepb.PrivateOrderStatus_PRIVATE_ORDER_STATUS_OPEN,
	}}), nil
}

func (f *privateOrdersFake) GetOpenOrders(_ context.Context, req *connect.Request[privatepb.GetOpenOrdersRequest]) (*connect.Response[privatepb.GetOpenOrdersResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.listAccount = req.Msg.GetAccountId()
	f.listMarket = req.Msg.GetMarketId()
	f.listPageSize = req.Msg.GetPageSize()
	f.listPageToken = req.Msg.GetPageToken()
	return connect.NewResponse(&privatepb.GetOpenOrdersResponse{Orders: []*privatepb.PrivateOrder{{
		OrderId: "77", AccountId: req.Msg.GetAccountId(), MarketId: "BTC-USDT",
		Status: privatepb.PrivateOrderStatus_PRIVATE_ORDER_STATUS_OPEN,
	}}}), nil
}

type marketFake struct{}

func (marketFake) GetMarket(_ context.Context, id string) (*marketpb.Market, error) {
	return &marketpb.Market{MarketId: id}, nil
}

func newRPCTestApp(t *testing.T, cfg config.Config, deps Dependencies) *App {
	t.Helper()
	app, err := NewWithDependencies(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), deps)
	if err != nil {
		t.Fatal(err)
	}
	return app
}

func validPublicSubmit() *publicpb.SubmitLimitOrderRequest {
	return &publicpb.SubmitLimitOrderRequest{Order: &orderpb.LimitOrderSubmission{
		ClientOrderId: "client-1", MarketId: "BTC-USDT", Side: orderpb.OrderSide_ORDER_SIDE_BUY,
		TimeInForce: orderpb.TimeInForce_TIME_IN_FORCE_GTC, Price: "100.00", Quantity: "0.50",
	}}
}

func TestBootstrapPublicAndProtectedRPCRoutes(t *testing.T) {
	backend := &privateOrdersFake{}
	path, handler := orderv1alpha1connect.NewOrderServiceHandler(backend)
	upstreamMux := http.NewServeMux()
	upstreamMux.Handle(path, handler)
	upstreamServer := httptest.NewServer(upstreamMux)
	defer upstreamServer.Close()

	cfg := config.Defaults()
	cfg.HTTP.OrderServiceURL = upstreamServer.URL
	app := newRPCTestApp(t, cfg, Dependencies{Verifier: verifierFake{}, Markets: marketFake{}})
	gateway := httptest.NewServer(app.Handler())
	defer gateway.Close()
	trading := apiv1alpha1connect.NewTradingServiceClient(gateway.Client(), gateway.URL)
	market := apiv1alpha1connect.NewMarketServiceClient(gateway.Client(), gateway.URL)

	// Market remains public and uses a provided dependency.
	mr, err := market.GetMarket(context.Background(), connect.NewRequest(&publicpb.GetMarketRequest{MarketId: "BTC-USDT"}))
	if err != nil || mr.Msg.Market.GetMarketId() != "BTC-USDT" {
		t.Fatalf("market: %v %v", mr, err)
	}

	// Protected operation must reject unauthenticated clients before forwarding.
	_, err = trading.SubmitLimitOrder(context.Background(), connect.NewRequest(validPublicSubmit()))
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("missing auth: %v", err)
	}

	req := connect.NewRequest(validPublicSubmit())
	req.Header().Set("Authorization", "Bearer valid-token")
	req.Header().Set("X-Account-ID", "attacker-999")
	req.Header().Set("X-Request-ID", "attacker-trace-id")
	resp, err := trading.SubmitLimitOrder(context.Background(), req)
	if err != nil {
		t.Fatalf("valid order: %v", err)
	}
	if resp.Msg.GetOrderId() != "77" || resp.Msg.GetStatus() != orderpb.OrderStatus_ORDER_STATUS_OPEN {
		t.Fatalf("unexpected response: %v", resp.Msg)
	}

	backend.mu.Lock()
	account, authHeader, requestID, calls := backend.account, backend.authorization, backend.requestID, backend.calls
	backend.mu.Unlock()
	if calls != 1 || account != "trusted-42" {
		t.Fatalf("untrusted account or wrong number of calls: %s %d", account, calls)
	}
	if authHeader != "" {
		t.Fatalf("client credentials leaked upstream")
	}
	if requestID == "" || requestID == "attacker-trace-id" {
		t.Fatalf("request ID was not gateway-generated: %q", requestID)
	}

	// Private paths must never be exposed by the public Gateway.
	privateURL := gateway.URL + orderv1alpha1connect.OrderServiceSubmitLimitOrderProcedure
	raw, err := gateway.Client().Post(privateURL, "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Body.Close()
	if raw.StatusCode != http.StatusNotFound {
		t.Fatalf("private path exposed: %d", raw.StatusCode)
	}
}

func TestBootstrapDefaultsFailClosed(t *testing.T) {
	app := newRPCTestApp(t, config.Defaults(), Dependencies{})
	gateway := httptest.NewServer(app.Handler())
	defer gateway.Close()
	client := apiv1alpha1connect.NewTradingServiceClient(gateway.Client(), gateway.URL)
	req := connect.NewRequest(validPublicSubmit())
	req.Header().Set("Authorization", "Bearer any-token")
	if _, err := client.SubmitLimitOrder(context.Background(), req); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("production placeholder must deny credentials, got %v", err)
	}
	market := apiv1alpha1connect.NewMarketServiceClient(gateway.Client(), gateway.URL)
	if _, err := market.GetMarket(context.Background(), connect.NewRequest(&publicpb.GetMarketRequest{MarketId: "BTC-USDT"})); connect.CodeOf(err) != connect.CodeUnimplemented {
		t.Fatalf("market without configured reader: %v", err)
	}
	response, err := gateway.Client().Get(gateway.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatal("liveness must not require authentication")
	}
}

func TestBootstrapProtectedCancelAndQueryRoutes(t *testing.T) {
	backend := &privateOrdersFake{}
	path, handler := orderv1alpha1connect.NewOrderServiceHandler(backend)
	privateMux := http.NewServeMux()
	privateMux.Handle(path, handler)
	upstream := httptest.NewServer(privateMux)
	defer upstream.Close()

	cfg := config.Defaults()
	cfg.HTTP.OrderServiceURL = upstream.URL
	app := newRPCTestApp(t, cfg, Dependencies{Verifier: verifierFake{}})
	gateway := httptest.NewServer(app.Handler())
	defer gateway.Close()
	client := apiv1alpha1connect.NewTradingServiceClient(gateway.Client(), gateway.URL)

	// The entire generated TradingService stays behind the Bearer boundary.
	_, err := client.CancelOrder(context.Background(), connect.NewRequest(&publicpb.CancelOrderRequest{OrderId: "77"}))
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("cancel without token: %v", err)
	}
	_, err = client.GetOrder(context.Background(), connect.NewRequest(&publicpb.GetOrderRequest{OrderId: "77"}))
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("get without token: %v", err)
	}
	_, err = client.GetOpenOrders(context.Background(), connect.NewRequest(&publicpb.GetOpenOrdersRequest{}))
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("list without token: %v", err)
	}

	cancel := connect.NewRequest(&publicpb.CancelOrderRequest{OrderId: "77"})
	cancel.Header().Set("Authorization", "Bearer valid-token")
	cancel.Header().Set("X-Account-ID", "forged-account")
	cancelResp, err := client.CancelOrder(context.Background(), cancel)
	if err != nil || cancelResp.Msg.GetStatus() != publicpb.CancelRequestStatus_CANCEL_REQUEST_STATUS_PENDING {
		t.Fatalf("cancel via Gateway: %v %v", cancelResp, err)
	}

	get := connect.NewRequest(&publicpb.GetOrderRequest{OrderId: "77"})
	get.Header().Set("Authorization", "Bearer valid-token")
	get.Header().Set("X-Account-ID", "forged-account")
	getResp, err := client.GetOrder(context.Background(), get)
	if err != nil || getResp.Msg.GetOrder().GetStatus() != publicpb.OrderViewStatus_ORDER_VIEW_STATUS_OPEN {
		t.Fatalf("query via Gateway: %v %v", getResp, err)
	}

	list := connect.NewRequest(&publicpb.GetOpenOrdersRequest{MarketId: "BTC-USDT", PageSize: 20, PageToken: "opaque-1"})
	list.Header().Set("Authorization", "Bearer valid-token")
	list.Header().Set("X-Account-ID", "forged-account")
	listResp, err := client.GetOpenOrders(context.Background(), list)
	if err != nil || len(listResp.Msg.GetOrders()) != 1 {
		t.Fatalf("list via Gateway: %v %v", listResp, err)
	}

	backend.mu.Lock()
	cancelAccount, getAccount, listAccount := backend.cancelAccount, backend.getAccount, backend.listAccount
	market, size, token := backend.listMarket, backend.listPageSize, backend.listPageToken
	backend.mu.Unlock()
	if cancelAccount != "trusted-42" || getAccount != "trusted-42" || listAccount != "trusted-42" || market != "BTC-USDT" || size != 20 || token != "opaque-1" {
		t.Fatalf("upstream identity or pagination mismatch: cancel=%q get=%q list=%q %q %d %q", cancelAccount, getAccount, listAccount, market, size, token)
	}
}
