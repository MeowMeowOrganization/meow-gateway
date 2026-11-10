// Package order provides a typed, private Connect-RPC adapter. It owns no
// financial decisions, never forwards client credentials, and never retries
// non-idempotent order mutations implicitly.
package order

import (
	"context"
	"net/http"
	"time"

	"connectrpc.com/connect"
	privatepb "github.com/MeowMeowOrganization/meow-contracts/gen/go/meow/exchange/private/order/v1alpha1"
	"github.com/MeowMeowOrganization/meow-contracts/gen/go/meow/exchange/private/order/v1alpha1/orderv1alpha1connect"
	"github.com/MeowMeowOrganization/meow-gateway/internal/middleware"
)

// Client is a narrow adapter over generated private Order Service RPCs.
// The gateway's publicly exposed services never register these private paths.
type Client struct {
	client    orderv1alpha1connect.OrderServiceClient
	transport *http.Transport
	timeout   time.Duration
}

func New(url string, timeout time.Duration) *Client {
	// Do not add http.Client.Timeout: each call gets a deadline derived from
	// the original RPC context, so the shorter of the two deadlines applies.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	return &Client{
		client:    orderv1alpha1connect.NewOrderServiceClient(&http.Client{Transport: transport}, url),
		transport: transport,
		timeout:   timeout,
	}
}

// CloseIdleConnections releases idle private-service sockets when the gateway stops.
func (c *Client) CloseIdleConnections() { c.transport.CloseIdleConnections() }

func (c *Client) callContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, c.timeout)
}

func request[T any](ctx context.Context, msg *T) *connect.Request[T] {
	req := connect.NewRequest(msg)
	if id, ok := middleware.RequestID(ctx); ok {
		req.Header().Set(middleware.RequestIDHeader, id)
	}
	// In particular: never copy inbound Authorization or X-Account-ID.
	return req
}

func (c *Client) SubmitLimitOrder(ctx context.Context, msg *privatepb.SubmitLimitOrderRequest) (*privatepb.SubmitLimitOrderResponse, error) {
	ctx, cancel := c.callContext(ctx)
	defer cancel()
	resp, err := c.client.SubmitLimitOrder(ctx, request(ctx, msg))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

func (c *Client) CancelOrder(ctx context.Context, msg *privatepb.CancelOrderRequest) (*privatepb.CancelOrderResponse, error) {
	ctx, cancel := c.callContext(ctx)
	defer cancel()
	resp, err := c.client.CancelOrder(ctx, request(ctx, msg))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

func (c *Client) GetOrder(ctx context.Context, msg *privatepb.GetOrderRequest) (*privatepb.GetOrderResponse, error) {
	ctx, cancel := c.callContext(ctx)
	defer cancel()
	resp, err := c.client.GetOrder(ctx, request(ctx, msg))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

func (c *Client) GetOpenOrders(ctx context.Context, msg *privatepb.GetOpenOrdersRequest) (*privatepb.GetOpenOrdersResponse, error) {
	ctx, cancel := c.callContext(ctx)
	defer cancel()
	resp, err := c.client.GetOpenOrders(ctx, request(ctx, msg))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

func (c *Client) GetOrderHistory(ctx context.Context, msg *privatepb.GetOrderHistoryRequest) (*privatepb.GetOrderHistoryResponse, error) {
	ctx, cancel := c.callContext(ctx)
	defer cancel()
	resp, err := c.client.GetOrderHistory(ctx, request(ctx, msg))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

func (c *Client) GetOrderTrades(ctx context.Context, msg *privatepb.GetOrderTradesRequest) (*privatepb.GetOrderTradesResponse, error) {
	ctx, cancel := c.callContext(ctx)
	defer cancel()
	resp, err := c.client.GetOrderTrades(ctx, request(ctx, msg))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

func (c *Client) GetTradeHistory(ctx context.Context, msg *privatepb.GetTradeHistoryRequest) (*privatepb.GetTradeHistoryResponse, error) {
	ctx, cancel := c.callContext(ctx)
	defer cancel()
	resp, err := c.client.GetTradeHistory(ctx, request(ctx, msg))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}
