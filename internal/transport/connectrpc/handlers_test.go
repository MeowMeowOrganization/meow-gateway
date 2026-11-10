package connectrpc

import (
	"context"
	"errors"
	"strings"
	"testing"

	"connectrpc.com/connect"
	publicpb "github.com/MeowMeowOrganization/meow-contracts/gen/go/meow/exchange/api/v1alpha1"
	marketpb "github.com/MeowMeowOrganization/meow-contracts/gen/go/meow/exchange/market/v1alpha1"
	orderpb "github.com/MeowMeowOrganization/meow-contracts/gen/go/meow/exchange/order/v1alpha1"
	privatepb "github.com/MeowMeowOrganization/meow-contracts/gen/go/meow/exchange/private/order/v1alpha1"
	"github.com/MeowMeowOrganization/meow-gateway/internal/auth"
	"github.com/MeowMeowOrganization/meow-gateway/internal/edgeerrors"
)

type fakeOrders struct {
	calls    int
	req      *privatepb.SubmitLimitOrderRequest
	response *privatepb.SubmitLimitOrderResponse
	err      error

	cancelCalls    int
	cancelReq      *privatepb.CancelOrderRequest
	cancelResponse *privatepb.CancelOrderResponse
	cancelErr      error

	getCalls    int
	getReq      *privatepb.GetOrderRequest
	getResponse *privatepb.GetOrderResponse
	getErr      error

	listCalls    int
	listReq      *privatepb.GetOpenOrdersRequest
	listResponse *privatepb.GetOpenOrdersResponse
	listErr      error
}

func (f *fakeOrders) SubmitLimitOrder(_ context.Context, req *privatepb.SubmitLimitOrderRequest) (*privatepb.SubmitLimitOrderResponse, error) {
	f.calls++
	f.req = req
	return f.response, f.err
}

func (f *fakeOrders) CancelOrder(_ context.Context, req *privatepb.CancelOrderRequest) (*privatepb.CancelOrderResponse, error) {
	f.cancelCalls++
	f.cancelReq = req
	return f.cancelResponse, f.cancelErr
}

func (f *fakeOrders) GetOrder(_ context.Context, req *privatepb.GetOrderRequest) (*privatepb.GetOrderResponse, error) {
	f.getCalls++
	f.getReq = req
	return f.getResponse, f.getErr
}

func (f *fakeOrders) GetOpenOrders(_ context.Context, req *privatepb.GetOpenOrdersRequest) (*privatepb.GetOpenOrdersResponse, error) {
	f.listCalls++
	f.listReq = req
	return f.listResponse, f.listErr
}

func validSubmission() *orderpb.LimitOrderSubmission {
	return &orderpb.LimitOrderSubmission{ClientOrderId: "client-1", MarketId: "BTC-USDT", Side: orderpb.OrderSide_ORDER_SIDE_BUY, TimeInForce: orderpb.TimeInForce_TIME_IN_FORCE_GTC, Price: "100.00", Quantity: "0.125"}
}

func principalContext(t *testing.T) context.Context {
	t.Helper()
	ctx, err := auth.WithPrincipal(context.Background(), auth.Principal{AccountID: "account-42", Permissions: []auth.Permission{auth.OrdersRead, auth.OrdersWrite}})
	if err != nil {
		t.Fatal(err)
	}
	return ctx
}

func TestTradingRejectsMissingPrincipalAndInvalidOrder(t *testing.T) {
	fake := &fakeOrders{}
	h := NewTradingHandler(fake)
	msg := connect.NewRequest(&publicpb.SubmitLimitOrderRequest{Order: validSubmission()})
	if _, err := h.SubmitLimitOrder(context.Background(), msg); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("missing principal: %v", err)
	}
	msg.Msg.Order.Price = "1e3"
	if _, err := h.SubmitLimitOrder(principalContext(t), msg); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("invalid price: %v", err)
	}
	if fake.calls != 0 {
		t.Fatal("invalid request reached backend")
	}
}

func TestTradingForwardsIdentityAndActualStatus(t *testing.T) {
	fake := &fakeOrders{response: &privatepb.SubmitLimitOrderResponse{Order: &orderpb.LimitOrder{
		OrderId: "123", AccountId: "account-42", ClientOrderId: "client-1", MarketId: "BTC-USDT",
		Side: orderpb.OrderSide_ORDER_SIDE_BUY, TimeInForce: orderpb.TimeInForce_TIME_IN_FORCE_GTC,
		Status: orderpb.OrderStatus_ORDER_STATUS_OPEN,
	}}}
	h := NewTradingHandler(fake)
	msg := connect.NewRequest(&publicpb.SubmitLimitOrderRequest{Order: validSubmission()})
	res, err := h.SubmitLimitOrder(principalContext(t), msg)
	if err != nil {
		t.Fatal(err)
	}
	if fake.calls != 1 || fake.req.AccountId != "account-42" || fake.req.Order.GetPrice() != "100.00" || fake.req.Order.GetQuantity() != "0.125" {
		t.Fatalf("incorrect private request: %+v", fake.req)
	}
	if res.Msg.GetOrderId() != "123" || res.Msg.GetStatus() != orderpb.OrderStatus_ORDER_STATUS_OPEN {
		t.Fatalf("incorrect public result: %v", res.Msg)
	}
}

func TestTradingSanitizesAndRejectsMalformedUpstream(t *testing.T) {
	fake := &fakeOrders{err: connect.NewError(connect.CodeUnavailable, errors.New("sensitive postgres connection string"))}
	h := NewTradingHandler(fake)
	msg := connect.NewRequest(&publicpb.SubmitLimitOrderRequest{Order: validSubmission()})
	_, err := h.SubmitLimitOrder(principalContext(t), msg)
	if connect.CodeOf(err) != connect.CodeUnavailable || err.Error() == fake.err.Error() {
		t.Fatalf("upstream error leaked: %v", err)
	}
	fake.err = nil
	fake.response = &privatepb.SubmitLimitOrderResponse{}
	_, err = h.SubmitLimitOrder(principalContext(t), msg)
	if connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("malformed response: %v", err)
	}
	fake.response.Order = &orderpb.LimitOrder{OrderId: "123", AccountId: "account-42", ClientOrderId: "client-1", MarketId: "BTC-USDT",
		Side: orderpb.OrderSide_ORDER_SIDE_BUY, TimeInForce: orderpb.TimeInForce_TIME_IN_FORCE_GTC,
		Status: orderpb.OrderStatus_ORDER_STATUS_UNSPECIFIED}
	_, err = h.SubmitLimitOrder(principalContext(t), msg)
	if connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("unspecified status: %v", err)
	}
}

type fakeMarkets struct {
	market *marketpb.Market
	err    error
	calls  int
}

func (f *fakeMarkets) GetMarket(_ context.Context, _ string) (*marketpb.Market, error) {
	f.calls++
	return f.market, f.err
}
func TestMarketHandler(t *testing.T) {
	valid := connect.NewRequest(&publicpb.GetMarketRequest{MarketId: "BTC-USDT"})
	if _, err := NewMarketHandler(nil).GetMarket(context.Background(), valid); connect.CodeOf(err) != connect.CodeUnimplemented {
		t.Fatalf("unconfigured market: %v", err)
	}
	fake := &fakeMarkets{market: &marketpb.Market{MarketId: "BTC-USDT"}}
	h := NewMarketHandler(fake)
	if _, err := h.GetMarket(context.Background(), connect.NewRequest(&publicpb.GetMarketRequest{MarketId: ""})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("invalid market: %v", err)
	}
	if fake.calls != 0 {
		t.Fatal("invalid market called reader")
	}
	res, err := h.GetMarket(context.Background(), valid)
	if err != nil || res.Msg.GetMarket().GetMarketId() != "BTC-USDT" {
		t.Fatalf("valid market: %v, %v", res, err)
	}
	fake.err = edgeerrors.New(edgeerrors.NotFound, errors.New("secret lookup error"))
	_, err = h.GetMarket(context.Background(), valid)
	if connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("not found: %v", err)
	}
	fake.err = nil
	fake.market = &marketpb.Market{MarketId: "ETH-USDT"}
	_, err = h.GetMarket(context.Background(), valid)
	if connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("mismatched market: %v", err)
	}
}

func privateOrder(id, account string) *privatepb.PrivateOrder {
	return &privatepb.PrivateOrder{
		OrderId: id, AccountId: account, ClientOrderId: "client-1", MarketId: "BTC-USDT",
		Side:         orderpb.OrderSide_ORDER_SIDE_BUY,
		TimeInForce:  orderpb.TimeInForce_TIME_IN_FORCE_GTC,
		PriceDecimal: "100.01", QuantityDecimal: "0.250",
		FilledBaseAtoms: "100000", RemainingBaseAtoms: "150000",
		Status: privatepb.PrivateOrderStatus_PRIVATE_ORDER_STATUS_ADMISSION_PENDING,
	}
}

func TestOrderRPCsRequireVerifiedPrincipal(t *testing.T) {
	f := &fakeOrders{}
	h := NewTradingHandler(f)
	assertAuth := func(err error) {
		t.Helper()
		if connect.CodeOf(err) != connect.CodeUnauthenticated {
			t.Fatalf("expected unauthenticated, got %v", err)
		}
	}
	_, err := h.CancelOrder(context.Background(), connect.NewRequest(&publicpb.CancelOrderRequest{OrderId: "42"}))
	assertAuth(err)
	_, err = h.GetOrder(context.Background(), connect.NewRequest(&publicpb.GetOrderRequest{OrderId: "42"}))
	assertAuth(err)
	_, err = h.GetOpenOrders(context.Background(), connect.NewRequest(&publicpb.GetOpenOrdersRequest{}))
	assertAuth(err)
	if f.cancelCalls != 0 || f.getCalls != 0 || f.listCalls != 0 {
		t.Fatal("unauthenticated call forwarded")
	}
}

func TestCancelOrderMapsAccountAndPreservesPendingStatus(t *testing.T) {
	f := &fakeOrders{cancelResponse: &privatepb.CancelOrderResponse{
		OrderId: "42", Status: privatepb.CancelRequestStatus_CANCEL_REQUEST_STATUS_PENDING,
		LifecycleStatus: orderpb.OrderStatus_ORDER_STATUS_OPEN,
		RejectionReason: "internal diagnostic must not be returned",
	}}
	h := NewTradingHandler(f)
	res, err := h.CancelOrder(principalContext(t), connect.NewRequest(&publicpb.CancelOrderRequest{OrderId: "42"}))
	if err != nil {
		t.Fatal(err)
	}
	if f.cancelCalls != 1 || f.cancelReq.GetAccountId() != "account-42" || f.cancelReq.GetOrderId() != "42" {
		t.Fatalf("incorrect cancel forwarding: %+v", f.cancelReq)
	}
	if res.Msg.GetStatus() != publicpb.CancelRequestStatus_CANCEL_REQUEST_STATUS_PENDING ||
		res.Msg.GetLifecycleStatus() != orderpb.OrderStatus_ORDER_STATUS_OPEN || res.Msg.GetOrderId() != "42" {
		t.Fatalf("incorrect pending response: %+v", res.Msg)
	}
	if strings.Contains(res.Msg.String(), "internal diagnostic") {
		t.Fatal("private rejection diagnostic exposed")
	}
}

func TestCancelOrderRejectsBadInputAndMalformedBackend(t *testing.T) {
	f := &fakeOrders{}
	h := NewTradingHandler(f)
	for _, id := range []string{"", "0", "001", "-5", "9223372036854775808"} {
		_, err := h.CancelOrder(principalContext(t), connect.NewRequest(&publicpb.CancelOrderRequest{OrderId: id}))
		if connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Fatalf("id %q: %v", id, err)
		}
	}
	if f.cancelCalls != 0 {
		t.Fatal("invalid request forwarded")
	}
	f.cancelResponse = &privatepb.CancelOrderResponse{OrderId: "43", Status: privatepb.CancelRequestStatus_CANCEL_REQUEST_STATUS_PENDING}
	_, err := h.CancelOrder(principalContext(t), connect.NewRequest(&publicpb.CancelOrderRequest{OrderId: "42"}))
	if connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("mismatched response: %v", err)
	}
	f.cancelResponse.OrderId = "42"
	f.cancelResponse.Status = privatepb.CancelRequestStatus_CANCEL_REQUEST_STATUS_UNSPECIFIED
	_, err = h.CancelOrder(principalContext(t), connect.NewRequest(&publicpb.CancelOrderRequest{OrderId: "42"}))
	if connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("unspecified response: %v", err)
	}
	f.cancelResponse.Status = 999
	_, err = h.CancelOrder(principalContext(t), connect.NewRequest(&publicpb.CancelOrderRequest{OrderId: "42"}))
	if connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("unknown response: %v", err)
	}
}

func TestGetOrderMapsIdentityAndProjectsPublicFields(t *testing.T) {
	f := &fakeOrders{getResponse: &privatepb.GetOrderResponse{Order: privateOrder("42", "account-42")}}
	f.getResponse.Order.MatcherRejectionReason = "secret matcher state"
	f.getResponse.Order.LastMarketSequence = "internal sequence"
	h := NewTradingHandler(f)
	res, err := h.GetOrder(principalContext(t), connect.NewRequest(&publicpb.GetOrderRequest{OrderId: "42"}))
	if err != nil {
		t.Fatal(err)
	}
	if f.getCalls != 1 || f.getReq.GetAccountId() != "account-42" || f.getReq.GetOrderId() != "42" {
		t.Fatalf("incorrect private query: %+v", f.getReq)
	}
	if res.Msg.GetOrder().GetStatus() != publicpb.OrderViewStatus_ORDER_VIEW_STATUS_ADMISSION_PENDING || res.Msg.GetOrder().GetPriceDecimal() != "100.01" {
		t.Fatalf("incorrect public view: %+v", res.Msg)
	}
	if strings.Contains(res.Msg.String(), "secret") || strings.Contains(res.Msg.String(), "account-42") || strings.Contains(res.Msg.String(), "internal sequence") {
		t.Fatalf("private fields exposed: %+v", res.Msg)
	}
}

func TestGetOrderDoesNotLeakOtherAccountsOrWrongIDs(t *testing.T) {
	f := &fakeOrders{getResponse: &privatepb.GetOrderResponse{Order: privateOrder("42", "attacker")}}
	h := NewTradingHandler(f)
	for _, wrong := range []string{"attacker", "account-42"} {
		f.getResponse.Order.AccountId = wrong
		f.getResponse.Order.OrderId = "43"
		if wrong == "attacker" {
			f.getResponse.Order.OrderId = "42"
		}
		_, err := h.GetOrder(principalContext(t), connect.NewRequest(&publicpb.GetOrderRequest{OrderId: "42"}))
		if connect.CodeOf(err) != connect.CodeUnavailable {
			t.Fatalf("wrong account or order returned: %v", err)
		}
	}
	if _, err := h.GetOrder(principalContext(t), connect.NewRequest(&publicpb.GetOrderRequest{OrderId: "1e3"})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("invalid id: %v", err)
	}
}

func TestGetOpenOrdersFiltersAndPreservesPageToken(t *testing.T) {
	f := &fakeOrders{listResponse: &privatepb.GetOpenOrdersResponse{
		Orders:        []*privatepb.PrivateOrder{privateOrder("42", "account-42"), privateOrder("43", "account-42")},
		NextPageToken: "opaque-cursor~A",
	}}
	h := NewTradingHandler(f)
	res, err := h.GetOpenOrders(principalContext(t), connect.NewRequest(&publicpb.GetOpenOrdersRequest{MarketId: "BTC-USDT", PageSize: 25, PageToken: "page~1"}))
	if err != nil {
		t.Fatal(err)
	}
	if f.listCalls != 1 || f.listReq.GetAccountId() != "account-42" || f.listReq.GetMarketId() != "BTC-USDT" || f.listReq.GetPageSize() != 25 || f.listReq.GetPageToken() != "page~1" {
		t.Fatalf("query not forwarded verbatim: %+v", f.listReq)
	}
	if len(res.Msg.GetOrders()) != 2 || res.Msg.GetNextPageToken() != "opaque-cursor~A" {
		t.Fatalf("incorrect pagination response: %+v", res.Msg)
	}
}

func TestGetOpenOrdersValidationAndTenantIsolation(t *testing.T) {
	f := &fakeOrders{listResponse: &privatepb.GetOpenOrdersResponse{Orders: []*privatepb.PrivateOrder{privateOrder("42", "attacker")}}}
	h := NewTradingHandler(f)
	for _, req := range []*publicpb.GetOpenOrdersRequest{
		{MarketId: "BTC USDT"}, {PageSize: -1}, {PageSize: 101}, {PageToken: "space token"},
	} {
		if _, err := h.GetOpenOrders(principalContext(t), connect.NewRequest(req)); connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Fatalf("invalid request not rejected: %v", err)
		}
	}
	if f.listCalls != 0 {
		t.Fatal("invalid query reached backend")
	}
	_, err := h.GetOpenOrders(principalContext(t), connect.NewRequest(&publicpb.GetOpenOrdersRequest{}))
	if connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("cross-account view exposed: %v", err)
	}
	f.listResponse.Orders[0].AccountId = "account-42"
	f.listResponse.Orders[0].Status = privatepb.PrivateOrderStatus_PRIVATE_ORDER_STATUS_UNSPECIFIED
	_, err = h.GetOpenOrders(principalContext(t), connect.NewRequest(&publicpb.GetOpenOrdersRequest{}))
	if connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("unknown status accepted: %v", err)
	}
	f.listResponse.Orders[0].Status = privatepb.PrivateOrderStatus_PRIVATE_ORDER_STATUS_OPEN
	f.listResponse.NextPageToken = "bad token"
	_, err = h.GetOpenOrders(principalContext(t), connect.NewRequest(&publicpb.GetOpenOrdersRequest{}))
	if connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("invalid backend cursor accepted: %v", err)
	}
}

func TestOrderRPCsSanitizeUpstreamErrors(t *testing.T) {
	secret := errors.New("secret connection credentials")
	f := &fakeOrders{
		cancelErr: connect.NewError(connect.CodeFailedPrecondition, secret),
		getErr:    connect.NewError(connect.CodeNotFound, secret),
		listErr:   connect.NewError(connect.CodeUnavailable, secret),
	}
	h := NewTradingHandler(f)
	for _, tc := range []struct {
		call func() error
		want connect.Code
	}{
		{func() error {
			_, e := h.CancelOrder(principalContext(t), connect.NewRequest(&publicpb.CancelOrderRequest{OrderId: "42"}))
			return e
		}, connect.CodeFailedPrecondition},
		{func() error {
			_, e := h.GetOrder(principalContext(t), connect.NewRequest(&publicpb.GetOrderRequest{OrderId: "42"}))
			return e
		}, connect.CodeNotFound},
		{func() error {
			_, e := h.GetOpenOrders(principalContext(t), connect.NewRequest(&publicpb.GetOpenOrdersRequest{}))
			return e
		}, connect.CodeUnavailable},
	} {
		err := tc.call()
		if connect.CodeOf(err) != tc.want || strings.Contains(err.Error(), "secret") {
			t.Fatalf("upstream error leaked or remapped: %v", err)
		}
	}
}

func TestExplicitPublicStatusMappings(t *testing.T) {
	for _, tc := range []struct {
		private privatepb.CancelRequestStatus
		public  publicpb.CancelRequestStatus
	}{
		{privatepb.CancelRequestStatus_CANCEL_REQUEST_STATUS_UNSPECIFIED, publicpb.CancelRequestStatus_CANCEL_REQUEST_STATUS_UNSPECIFIED},
		{privatepb.CancelRequestStatus_CANCEL_REQUEST_STATUS_PENDING, publicpb.CancelRequestStatus_CANCEL_REQUEST_STATUS_PENDING},
		{privatepb.CancelRequestStatus_CANCEL_REQUEST_STATUS_CONFIRMED, publicpb.CancelRequestStatus_CANCEL_REQUEST_STATUS_CONFIRMED},
		{privatepb.CancelRequestStatus_CANCEL_REQUEST_STATUS_REJECTED, publicpb.CancelRequestStatus_CANCEL_REQUEST_STATUS_REJECTED},
		{privatepb.CancelRequestStatus_CANCEL_REQUEST_STATUS_NOT_CANCELLABLE, publicpb.CancelRequestStatus_CANCEL_REQUEST_STATUS_NOT_CANCELLABLE},
	} {
		got, ok := publicCancelStatus(tc.private)
		if !ok || got != tc.public {
			t.Fatalf("cancel status %v => %v, %v", tc.private, got, ok)
		}
	}
	if _, ok := publicCancelStatus(999); ok {
		t.Fatal("unknown cancellation status accepted")
	}
	if got, ok := publicOrderStatus(privatepb.PrivateOrderStatus_PRIVATE_ORDER_STATUS_ADMISSION_PENDING); !ok || got != publicpb.OrderViewStatus_ORDER_VIEW_STATUS_ADMISSION_PENDING {
		t.Fatal("pending admission confused with accepted order")
	}
	if got, ok := publicOrderStatus(privatepb.PrivateOrderStatus_PRIVATE_ORDER_STATUS_ACCEPTED); !ok || got != publicpb.OrderViewStatus_ORDER_VIEW_STATUS_ACCEPTED {
		t.Fatal("accepted order mapping invalid")
	}
	if _, ok := publicOrderStatus(privatepb.PrivateOrderStatus_PRIVATE_ORDER_STATUS_UNSPECIFIED); ok {
		t.Fatal("unknown order state accepted")
	}
}

// A private backend returning another account's order must never cross the
// public tenant boundary, even if it is otherwise a successful RPC.
func TestSubmitRejectsMismatchedPrivateResponse(t *testing.T) {
	response := &privatepb.SubmitLimitOrderResponse{Order: &orderpb.LimitOrder{
		OrderId: "123", AccountId: "account-42", ClientOrderId: "client-1", MarketId: "BTC-USDT",
		Side: orderpb.OrderSide_ORDER_SIDE_BUY, TimeInForce: orderpb.TimeInForce_TIME_IN_FORCE_GTC,
		Status: orderpb.OrderStatus_ORDER_STATUS_ACCEPTED,
	}}
	f := &fakeOrders{response: response}
	h := NewTradingHandler(f)
	request := connect.NewRequest(&publicpb.SubmitLimitOrderRequest{Order: validSubmission()})
	check := func(reason string) {
		t.Helper()
		if _, err := h.SubmitLimitOrder(principalContext(t), request); connect.CodeOf(err) != connect.CodeUnavailable {
			t.Fatalf("%s: expected sanitized unavailable; got %v", reason, err)
		}
	}
	response.Order.AccountId = "someone-else"
	check("wrong account")
	response.Order.AccountId = "account-42"
	response.Order.ClientOrderId = "another-client-order"
	check("wrong client order ID")
	response.Order.ClientOrderId = "client-1"
	response.Order.MarketId = "ETH-USDT"
	check("wrong market")
	response.Order.MarketId = "BTC-USDT"
	response.Order.Side = orderpb.OrderSide_ORDER_SIDE_SELL
	check("wrong side")
	response.Order.Side = orderpb.OrderSide_ORDER_SIDE_BUY
	response.Order.TimeInForce = orderpb.TimeInForce_TIME_IN_FORCE_UNSPECIFIED
	check("wrong TIF")
	response.Order.TimeInForce = orderpb.TimeInForce_TIME_IN_FORCE_GTC
	response.Order.OrderId = "99999999999999999999"
	check("non-canonical order ID")
	response.Order.OrderId = "123"
	response.Order.Status = orderpb.OrderStatus(999)
	check("unknown status")
}

func TestTradingHandlerEnforcesPermissionsWithoutRouter(t *testing.T) {
	f := &fakeOrders{}
	h := NewTradingHandler(f)
	contextFor := func(perms ...auth.Permission) context.Context {
		t.Helper()
		ctx, err := auth.WithPrincipal(context.Background(), auth.Principal{AccountID: "account-42", Permissions: perms})
		if err != nil {
			t.Fatal(err)
		}
		return ctx
	}
	writeOnly := contextFor(auth.OrdersWrite)
	readOnly := contextFor(auth.OrdersRead)
	if _, err := h.SubmitLimitOrder(readOnly, connect.NewRequest(&publicpb.SubmitLimitOrderRequest{Order: validSubmission()})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("read-only principal could submit: %v", err)
	}
	if _, err := h.CancelOrder(readOnly, connect.NewRequest(&publicpb.CancelOrderRequest{OrderId: "42"})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("read-only principal could cancel: %v", err)
	}
	if _, err := h.GetOrder(writeOnly, connect.NewRequest(&publicpb.GetOrderRequest{OrderId: "42"})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("write-only principal could read: %v", err)
	}
	if _, err := h.GetOpenOrders(writeOnly, connect.NewRequest(&publicpb.GetOpenOrdersRequest{})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("write-only principal could list: %v", err)
	}
	if f.calls != 0 || f.cancelCalls != 0 || f.getCalls != 0 || f.listCalls != 0 {
		t.Fatal("unauthorized private call reached upstream")
	}
}

func TestCancelRejectsUnknownPrivateLifecycle(t *testing.T) {
	f := &fakeOrders{cancelResponse: &privatepb.CancelOrderResponse{
		OrderId: "42", Status: privatepb.CancelRequestStatus_CANCEL_REQUEST_STATUS_PENDING,
		LifecycleStatus: orderpb.OrderStatus(999),
	}}
	_, err := NewTradingHandler(f).CancelOrder(principalContext(t), connect.NewRequest(&publicpb.CancelOrderRequest{OrderId: "42"}))
	if connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("unknown backend lifecycle accepted: %v", err)
	}
}

func TestSubmitPreservesDurableAcceptedWithoutInventingExecution(t *testing.T) {
	f := &fakeOrders{response: &privatepb.SubmitLimitOrderResponse{Order: &orderpb.LimitOrder{
		OrderId: "123", AccountId: "account-42", ClientOrderId: "client-1", MarketId: "BTC-USDT",
		Side: orderpb.OrderSide_ORDER_SIDE_BUY, TimeInForce: orderpb.TimeInForce_TIME_IN_FORCE_GTC,
		Status: orderpb.OrderStatus_ORDER_STATUS_ACCEPTED,
	}}}
	res, err := NewTradingHandler(f).SubmitLimitOrder(principalContext(t), connect.NewRequest(&publicpb.SubmitLimitOrderRequest{Order: validSubmission()}))
	if err != nil {
		t.Fatal(err)
	}
	if res.Msg.GetStatus() != orderpb.OrderStatus_ORDER_STATUS_ACCEPTED {
		t.Fatalf("gateway invented a later execution state: %v", res.Msg.GetStatus())
	}
}
