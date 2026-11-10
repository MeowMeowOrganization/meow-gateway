package connectrpc

import (
	"errors"

	publicpb "github.com/MeowMeowOrganization/meow-contracts/gen/go/meow/exchange/api/v1alpha1"
	privatepb "github.com/MeowMeowOrganization/meow-contracts/gen/go/meow/exchange/private/order/v1alpha1"
	"github.com/MeowMeowOrganization/meow-gateway/internal/validation"
)

var errInvalidProjection = errors.New("invalid private order projection")

// publicCancelStatus uses an explicit exhaustive mapping; never rely on enum
// integer alignment between private and public protobuf packages.
func publicCancelStatus(status privatepb.CancelRequestStatus) (publicpb.CancelRequestStatus, bool) {
	switch status {
	case privatepb.CancelRequestStatus_CANCEL_REQUEST_STATUS_UNSPECIFIED:
		return publicpb.CancelRequestStatus_CANCEL_REQUEST_STATUS_UNSPECIFIED, true
	case privatepb.CancelRequestStatus_CANCEL_REQUEST_STATUS_PENDING:
		return publicpb.CancelRequestStatus_CANCEL_REQUEST_STATUS_PENDING, true
	case privatepb.CancelRequestStatus_CANCEL_REQUEST_STATUS_CONFIRMED:
		return publicpb.CancelRequestStatus_CANCEL_REQUEST_STATUS_CONFIRMED, true
	case privatepb.CancelRequestStatus_CANCEL_REQUEST_STATUS_REJECTED:
		return publicpb.CancelRequestStatus_CANCEL_REQUEST_STATUS_REJECTED, true
	case privatepb.CancelRequestStatus_CANCEL_REQUEST_STATUS_NOT_CANCELLABLE:
		return publicpb.CancelRequestStatus_CANCEL_REQUEST_STATUS_NOT_CANCELLABLE, true
	default:
		return 0, false
	}
}

func publicOrderStatus(status privatepb.PrivateOrderStatus) (publicpb.OrderViewStatus, bool) {
	switch status {
	case privatepb.PrivateOrderStatus_PRIVATE_ORDER_STATUS_ADMISSION_PENDING:
		return publicpb.OrderViewStatus_ORDER_VIEW_STATUS_ADMISSION_PENDING, true
	case privatepb.PrivateOrderStatus_PRIVATE_ORDER_STATUS_ADMISSION_REJECTED:
		return publicpb.OrderViewStatus_ORDER_VIEW_STATUS_ADMISSION_REJECTED, true
	case privatepb.PrivateOrderStatus_PRIVATE_ORDER_STATUS_ACCEPTED:
		return publicpb.OrderViewStatus_ORDER_VIEW_STATUS_ACCEPTED, true
	case privatepb.PrivateOrderStatus_PRIVATE_ORDER_STATUS_OPEN:
		return publicpb.OrderViewStatus_ORDER_VIEW_STATUS_OPEN, true
	case privatepb.PrivateOrderStatus_PRIVATE_ORDER_STATUS_PARTIALLY_FILLED:
		return publicpb.OrderViewStatus_ORDER_VIEW_STATUS_PARTIALLY_FILLED, true
	case privatepb.PrivateOrderStatus_PRIVATE_ORDER_STATUS_FILLED:
		return publicpb.OrderViewStatus_ORDER_VIEW_STATUS_FILLED, true
	case privatepb.PrivateOrderStatus_PRIVATE_ORDER_STATUS_CANCELED:
		return publicpb.OrderViewStatus_ORDER_VIEW_STATUS_CANCELED, true
	case privatepb.PrivateOrderStatus_PRIVATE_ORDER_STATUS_MATCHER_REJECTED:
		return publicpb.OrderViewStatus_ORDER_VIEW_STATUS_MATCHER_REJECTED, true
	default:
		return 0, false
	}
}

func projectOrder(o *privatepb.PrivateOrder, accountID string) (*publicpb.OrderView, error) {
	if o == nil || o.GetAccountId() != accountID || validation.OrderID(o.GetOrderId()) != nil {
		return nil, errInvalidProjection
	}
	status, ok := publicOrderStatus(o.GetStatus())
	if !ok {
		return nil, errInvalidProjection
	}
	cancel, ok := publicCancelStatus(o.GetCancelRequestStatus())
	if !ok {
		return nil, errInvalidProjection
	}
	// Never return the private message directly: it includes account_id,
	// provenance, normalized engine units, and internal rejection details.
	return &publicpb.OrderView{
		OrderId:             o.GetOrderId(),
		ClientOrderId:       o.GetClientOrderId(),
		MarketId:            o.GetMarketId(),
		Side:                o.GetSide(),
		TimeInForce:         o.GetTimeInForce(),
		PriceDecimal:        o.GetPriceDecimal(),
		QuantityDecimal:     o.GetQuantityDecimal(),
		FilledBaseAtoms:     o.GetFilledBaseAtoms(),
		RemainingBaseAtoms:  o.GetRemainingBaseAtoms(),
		Status:              status,
		CancelRequestStatus: cancel,
		CreatedAt:           o.GetCreatedAt(),
		UpdatedAt:           o.GetUpdatedAt(),
	}, nil
}
