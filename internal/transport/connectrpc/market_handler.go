package connectrpc

import (
	"context"

	"connectrpc.com/connect"
	publicpb "github.com/MeowMeowOrganization/meow-contracts/gen/go/meow/exchange/api/v1alpha1"
	marketpb "github.com/MeowMeowOrganization/meow-contracts/gen/go/meow/exchange/market/v1alpha1"
	"github.com/MeowMeowOrganization/meow-gateway/internal/edgeerrors"
	"github.com/MeowMeowOrganization/meow-gateway/internal/validation"
)

// MarketReader is a dependency boundary, not an invented market database or
// cache connection. No market read service contract is supplied in this ZIP.
type MarketReader interface {
	GetMarket(context.Context, string) (*marketpb.Market, error)
}

type MarketHandler struct{ reader MarketReader }

func NewMarketHandler(reader MarketReader) *MarketHandler { return &MarketHandler{reader: reader} }

func (h *MarketHandler) GetMarket(ctx context.Context, req *connect.Request[publicpb.GetMarketRequest]) (*connect.Response[publicpb.GetMarketResponse], error) {
	if req == nil || req.Msg == nil || validation.Identifier(req.Msg.GetMarketId()) != nil {
		return nil, edgeerrors.ToConnect(edgeerrors.New(edgeerrors.InvalidArgument, nil))
	}
	if h.reader == nil {
		return nil, edgeerrors.ToConnect(edgeerrors.New(edgeerrors.Unimplemented, nil))
	}
	market, err := h.reader.GetMarket(ctx, req.Msg.GetMarketId())
	if err != nil {
		return nil, edgeerrors.ToConnect(err)
	}
	if market == nil || market.GetMarketId() != req.Msg.GetMarketId() {
		return nil, edgeerrors.ToConnect(edgeerrors.New(edgeerrors.Unavailable, nil))
	}
	return connect.NewResponse(&publicpb.GetMarketResponse{Market: market}), nil
}
