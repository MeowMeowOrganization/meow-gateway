package validation

import (
	"errors"
	"testing"

	orderpb "github.com/MeowMeowOrganization/meow-contracts/gen/go/meow/exchange/order/v1alpha1"
)

func validOrder() *orderpb.LimitOrderSubmission {
	return &orderpb.LimitOrderSubmission{ClientOrderId: "client-1", MarketId: "BTC-USDT", Side: orderpb.OrderSide_ORDER_SIDE_BUY, TimeInForce: orderpb.TimeInForce_TIME_IN_FORCE_GTC, Price: "42000.500", Quantity: "0.125"}
}

func TestIdentifier(t *testing.T) {
	for _, valid := range []string{"BTC-USDT", "client:1", "1", "a_b.c"} {
		if err := Identifier(valid); err != nil {
			t.Errorf("valid %q: %v", valid, err)
		}
	}
	for _, invalid := range []string{"", " abc", "abc ", "a\nb", "雪", string(make([]byte, 129))} {
		if err := Identifier(invalid); !errors.Is(err, ErrInvalidField) {
			t.Errorf("invalid %q: %v", invalid, err)
		}
	}
}

func TestLimitOrderSubmission(t *testing.T) {
	if err := LimitOrderSubmission(validOrder()); err != nil {
		t.Fatal(err)
	}
	if err := LimitOrderSubmission(nil); err == nil {
		t.Fatal("missing order allowed")
	}
	cases := map[string]func(*orderpb.LimitOrderSubmission){
		"client":             func(v *orderpb.LimitOrderSubmission) { v.ClientOrderId = "" },
		"market":             func(v *orderpb.LimitOrderSubmission) { v.MarketId = "BTC USDT" },
		"side":               func(v *orderpb.LimitOrderSubmission) { v.Side = orderpb.OrderSide_ORDER_SIDE_UNSPECIFIED },
		"unknown side":       func(v *orderpb.LimitOrderSubmission) { v.Side = orderpb.OrderSide(999) },
		"tif":                func(v *orderpb.LimitOrderSubmission) { v.TimeInForce = orderpb.TimeInForce_TIME_IN_FORCE_UNSPECIFIED },
		"negative price":     func(v *orderpb.LimitOrderSubmission) { v.Price = "-1" },
		"scientific price":   func(v *orderpb.LimitOrderSubmission) { v.Price = "1e9" },
		"zero price":         func(v *orderpb.LimitOrderSubmission) { v.Price = "0.00" },
		"zero quantity":      func(v *orderpb.LimitOrderSubmission) { v.Quantity = "0" },
		"malformed quantity": func(v *orderpb.LimitOrderSubmission) { v.Quantity = "1." },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			v := validOrder()
			mutate(v)
			if err := LimitOrderSubmission(v); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
}
