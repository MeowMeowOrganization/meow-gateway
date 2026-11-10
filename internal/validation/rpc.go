package validation

import (
	"errors"
	"fmt"

	orderpb "github.com/MeowMeowOrganization/meow-contracts/gen/go/meow/exchange/order/v1alpha1"
)

var ErrInvalidField = errors.New("invalid request field")

// Identifier applies only bounded ASCII / control-character hygiene.
// Canonical account ownership, market naming and idempotency stay upstream.
func Identifier(value string) error {
	if len(value) == 0 || len(value) > 128 {
		return ErrInvalidField
	}
	for i := 0; i < len(value); i++ {
		if value[i] < '!' || value[i] > '~' {
			return ErrInvalidField
		}
	}
	return nil
}

// LimitOrderSubmission checks public input syntax without making trading-policy
// decisions (min notional, lot size, price tick, account balances, etc.).
func LimitOrderSubmission(order *orderpb.LimitOrderSubmission) error {
	if order == nil {
		return fmt.Errorf("order: %w", ErrInvalidField)
	}
	if err := Identifier(order.GetClientOrderId()); err != nil {
		return fmt.Errorf("client_order_id: %w", err)
	}
	if err := Identifier(order.GetMarketId()); err != nil {
		return fmt.Errorf("market_id: %w", err)
	}
	if order.GetSide() != orderpb.OrderSide_ORDER_SIDE_BUY && order.GetSide() != orderpb.OrderSide_ORDER_SIDE_SELL {
		return fmt.Errorf("side: %w", ErrInvalidField)
	}
	if order.GetTimeInForce() != orderpb.TimeInForce_TIME_IN_FORCE_GTC {
		return fmt.Errorf("time_in_force: %w", ErrInvalidField)
	}
	if err := PositiveDecimal(order.GetPrice()); err != nil {
		return fmt.Errorf("price: %w", err)
	}
	if err := PositiveDecimal(order.GetQuantity()); err != nil {
		return fmt.Errorf("quantity: %w", err)
	}
	return nil
}
