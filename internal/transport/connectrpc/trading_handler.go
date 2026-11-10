// Package connectrpc adapts public protobuf RPC contracts to trusted backend
// interfaces. This package does not make trading, ledger, or matching decisions.
package connectrpc

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	publicpb "github.com/MeowMeowOrganization/meow-contracts/gen/go/meow/exchange/api/v1alpha1"
	"github.com/MeowMeowOrganization/meow-contracts/gen/go/meow/exchange/api/v1alpha1/apiv1alpha1connect"
	privatepb "github.com/MeowMeowOrganization/meow-contracts/gen/go/meow/exchange/private/order/v1alpha1"
	"github.com/MeowMeowOrganization/meow-gateway/internal/auth"
	"github.com/MeowMeowOrganization/meow-gateway/internal/edgeerrors"
	"github.com/MeowMeowOrganization/meow-gateway/internal/validation"
)

// OrderSubmitter is implemented by the private Connect client and by handler
// fakes. Each method accepts a private request populated with trusted identity.
type OrderSubmitter interface {
	SubmitLimitOrder(context.Context, *privatepb.SubmitLimitOrderRequest) (*privatepb.SubmitLimitOrderResponse, error)
	CancelOrder(context.Context, *privatepb.CancelOrderRequest) (*privatepb.CancelOrderResponse, error)
	GetOrder(context.Context, *privatepb.GetOrderRequest) (*privatepb.GetOrderResponse, error)
	GetOpenOrders(context.Context, *privatepb.GetOpenOrdersRequest) (*privatepb.GetOpenOrdersResponse, error)
}

type TradingHandler struct{ orders OrderSubmitter }

var _ apiv1alpha1connect.TradingServiceHandler = (*TradingHandler)(nil)

func NewTradingHandler(orders OrderSubmitter) *TradingHandler {
	return &TradingHandler{orders: orders}
}

func verifiedAccount(ctx context.Context, required auth.Permission) (string, error) {
	principal, ok := auth.PrincipalFromContext(ctx)
	if !ok || principal.AccountID == "" {
		return "", edgeerrors.ToConnect(edgeerrors.New(edgeerrors.Unauthenticated, auth.ErrInvalidCredentials))
	}
	// Defense in depth: the HTTP router also enforces the permission table,
	// but individual handlers must remain fail-closed if routing changes.
	if !principal.HasPermission(required) {
		return "", edgeerrors.ToConnect(edgeerrors.New(edgeerrors.PermissionDenied, nil))
	}
	return principal.AccountID, nil
}

func invalidRequest(err error) error {
	return edgeerrors.ToConnect(edgeerrors.New(edgeerrors.InvalidArgument, err))
}

func malformedBackend() error {
	return edgeerrors.ToConnect(edgeerrors.New(edgeerrors.Unavailable, errors.New("malformed private order response")))
}

func (h *TradingHandler) SubmitLimitOrder(ctx context.Context, req *connect.Request[publicpb.SubmitLimitOrderRequest]) (*connect.Response[publicpb.SubmitLimitOrderResponse], error) {
	accountID, err := verifiedAccount(ctx, auth.OrdersWrite)
	if err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil {
		return nil, invalidRequest(errors.New("missing request"))
	}
	if err := validation.LimitOrderSubmission(req.Msg.GetOrder()); err != nil {
		return nil, invalidRequest(err)
	}
	if h.orders == nil {
		return nil, edgeerrors.ToConnect(edgeerrors.New(edgeerrors.Unavailable, nil))
	}
	// Account ID is supplied exclusively from trusted context.
	res, err := h.orders.SubmitLimitOrder(ctx, &privatepb.SubmitLimitOrderRequest{
		AccountId: accountID,
		Order:     req.Msg.GetOrder(),
	})
	if err != nil {
		return nil, edgeerrors.ToConnect(err)
	}
	// The response is private and must be checked before projecting anything.
	// An upstream bug must not disclose another account's order ID or status.
	if res == nil || res.Order == nil ||
		validation.OrderID(res.Order.GetOrderId()) != nil ||
		res.Order.GetAccountId() != accountID ||
		res.Order.GetClientOrderId() != req.Msg.GetOrder().GetClientOrderId() ||
		res.Order.GetMarketId() != req.Msg.GetOrder().GetMarketId() ||
		res.Order.GetSide() != req.Msg.GetOrder().GetSide() ||
		res.Order.GetTimeInForce() != req.Msg.GetOrder().GetTimeInForce() ||
		!validSubmissionStatus(res.Order.GetStatus()) {
		return nil, malformedBackend()
	}
	// Success means the Order Service returned its authoritative result.
	// Do not upgrade ACCEPTED into OPEN or FILLED. This legacy private reply
	// cannot represent ADMISSION_PENDING; the Order Service must not return it
	// until durable admission is complete (see docs/CEX22.md).
	return connect.NewResponse(&publicpb.SubmitLimitOrderResponse{
		OrderId: res.Order.GetOrderId(),
		Status:  res.Order.GetStatus(),
	}), nil
}

func (h *TradingHandler) CancelOrder(ctx context.Context, req *connect.Request[publicpb.CancelOrderRequest]) (*connect.Response[publicpb.CancelOrderResponse], error) {
	accountID, err := verifiedAccount(ctx, auth.OrdersWrite)
	if err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil {
		return nil, invalidRequest(errors.New("missing request"))
	}
	if err := validation.OrderID(req.Msg.GetOrderId()); err != nil {
		return nil, invalidRequest(err)
	}
	if h.orders == nil {
		return nil, edgeerrors.ToConnect(edgeerrors.New(edgeerrors.Unavailable, nil))
	}
	res, err := h.orders.CancelOrder(ctx, &privatepb.CancelOrderRequest{
		AccountId: accountID,
		OrderId:   req.Msg.GetOrderId(),
	})
	if err != nil {
		return nil, edgeerrors.ToConnect(err)
	}
	if res == nil || res.GetOrderId() != req.Msg.GetOrderId() {
		return nil, malformedBackend()
	}
	status, ok := publicCancelStatus(res.GetStatus())
	if !ok || status == publicpb.CancelRequestStatus_CANCEL_REQUEST_STATUS_UNSPECIFIED ||
		!validLifecycleStatus(res.GetLifecycleStatus()) {
		return nil, malformedBackend()
	}
	// PENDING means an enqueued cancel intent; it is not confirmation.
	// Never leak a free-form internal rejection_reason to public clients.
	return connect.NewResponse(&publicpb.CancelOrderResponse{
		OrderId:         res.GetOrderId(),
		Status:          status,
		LifecycleStatus: res.GetLifecycleStatus(),
	}), nil
}

func (h *TradingHandler) GetOrder(ctx context.Context, req *connect.Request[publicpb.GetOrderRequest]) (*connect.Response[publicpb.GetOrderResponse], error) {
	accountID, err := verifiedAccount(ctx, auth.OrdersRead)
	if err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil {
		return nil, invalidRequest(errors.New("missing request"))
	}
	if err := validation.OrderID(req.Msg.GetOrderId()); err != nil {
		return nil, invalidRequest(err)
	}
	if h.orders == nil {
		return nil, edgeerrors.ToConnect(edgeerrors.New(edgeerrors.Unavailable, nil))
	}
	res, err := h.orders.GetOrder(ctx, &privatepb.GetOrderRequest{
		AccountId: accountID,
		OrderId:   req.Msg.GetOrderId(),
	})
	if err != nil {
		return nil, edgeerrors.ToConnect(err)
	}
	if res == nil {
		return nil, malformedBackend()
	}
	view, err := projectOrder(res.GetOrder(), accountID)
	if err != nil || view.GetOrderId() != req.Msg.GetOrderId() {
		return nil, malformedBackend()
	}
	return connect.NewResponse(&publicpb.GetOrderResponse{Order: view}), nil
}

func (h *TradingHandler) GetOpenOrders(ctx context.Context, req *connect.Request[publicpb.GetOpenOrdersRequest]) (*connect.Response[publicpb.GetOpenOrdersResponse], error) {
	accountID, err := verifiedAccount(ctx, auth.OrdersRead)
	if err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil {
		return nil, invalidRequest(errors.New("missing request"))
	}
	if err := validation.OpenOrdersQuery(req.Msg.GetMarketId(), req.Msg.GetPageSize(), req.Msg.GetPageToken()); err != nil {
		return nil, invalidRequest(err)
	}
	if h.orders == nil {
		return nil, edgeerrors.ToConnect(edgeerrors.New(edgeerrors.Unavailable, nil))
	}
	res, err := h.orders.GetOpenOrders(ctx, &privatepb.GetOpenOrdersRequest{
		AccountId: accountID,
		MarketId:  req.Msg.GetMarketId(),
		PageSize:  req.Msg.GetPageSize(),
		PageToken: req.Msg.GetPageToken(),
	})
	if err != nil {
		return nil, edgeerrors.ToConnect(err)
	}
	if res == nil || len(res.GetOrders()) > 100 || validation.OpenOrdersQuery("", 0, res.GetNextPageToken()) != nil {
		return nil, malformedBackend()
	}
	views := make([]*publicpb.OrderView, 0, len(res.GetOrders()))
	for _, privateOrder := range res.GetOrders() {
		view, err := projectOrder(privateOrder, accountID)
		if err != nil || (req.Msg.GetMarketId() != "" && view.GetMarketId() != req.Msg.GetMarketId()) {
			return nil, malformedBackend()
		}
		views = append(views, view)
	}
	return connect.NewResponse(&publicpb.GetOpenOrdersResponse{
		Orders:        views,
		NextPageToken: res.GetNextPageToken(),
	}), nil
}
