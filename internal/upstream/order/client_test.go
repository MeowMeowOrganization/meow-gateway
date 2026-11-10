package order

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"
	privatepb "github.com/MeowMeowOrganization/meow-contracts/gen/go/meow/exchange/private/order/v1alpha1"
	"github.com/MeowMeowOrganization/meow-contracts/gen/go/meow/exchange/private/order/v1alpha1/orderv1alpha1connect"
)

type upstreamFake struct {
	orderv1alpha1connect.UnimplementedOrderServiceHandler
}

func (upstreamFake) GetOrder(_ context.Context, req *connect.Request[privatepb.GetOrderRequest]) (*connect.Response[privatepb.GetOrderResponse], error) {
	if req.Header().Get("Authorization") != "" {
		return nil, connect.NewError(connect.CodePermissionDenied, context.Canceled)
	}
	return connect.NewResponse(&privatepb.GetOrderResponse{Order: &privatepb.PrivateOrder{OrderId: req.Msg.GetOrderId(), AccountId: req.Msg.GetAccountId()}}), nil
}

func TestTypedPrivateOrderClient(t *testing.T) {
	path, handler := orderv1alpha1connect.NewOrderServiceHandler(upstreamFake{})
	mux := http.NewServeMux()
	mux.Handle(path, handler)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	client := New(srv.URL, 2*time.Second)
	res, err := client.GetOrder(context.Background(), &privatepb.GetOrderRequest{AccountId: "account-1", OrderId: "123"})
	if err != nil {
		t.Fatal(err)
	}
	if res.GetOrder().GetOrderId() != "123" || res.GetOrder().GetAccountId() != "account-1" {
		t.Fatalf("unexpected private response: %v", res)
	}
}

func TestPrivateClientHonorsContextDeadline(t *testing.T) {
	path, handler := orderv1alpha1connect.NewOrderServiceHandler(upstreamFake{})
	mux := http.NewServeMux()
	mux.Handle(path, handler)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	client := New(srv.URL, time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := client.GetOrder(ctx, &privatepb.GetOrderRequest{AccountId: "account-1", OrderId: "123"})
	if err == nil {
		t.Fatal("canceled caller context ignored")
	}
	if connect.CodeOf(err) != connect.CodeCanceled {
		t.Fatalf("got %v", err)
	}
}
