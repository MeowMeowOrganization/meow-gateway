package validation

import (
	"errors"
	"strings"
	"testing"
)

func TestOrderID(t *testing.T) {
	for _, id := range []string{"1", "42", "9223372036854775807"} {
		if err := OrderID(id); err != nil {
			t.Errorf("valid %q rejected: %v", id, err)
		}
	}
	for _, id := range []string{"", "0", "00", "001", "-1", "+1", "1.0", " 1", "1 ", "1e3", "１２", "9223372036854775808", "99999999999999999999"} {
		if err := OrderID(id); !errors.Is(err, ErrInvalidField) {
			t.Errorf("invalid %q accepted: %v", id, err)
		}
	}
}

func TestOpenOrdersQuery(t *testing.T) {
	for _, tc := range []struct {
		market string
		page   int32
		token  string
	}{
		{"", 0, ""},
		{"BTC-USDT", 50, "AA-._~9"},
		{"ETH-USDT", 100, strings.Repeat("A", 4096)},
	} {
		if err := OpenOrdersQuery(tc.market, tc.page, tc.token); err != nil {
			t.Errorf("valid %+v: %v", tc, err)
		}
	}
	for _, tc := range []struct {
		market string
		page   int32
		token  string
	}{
		{"bad market", 0, ""},
		{"BTC-USDT", -1, ""},
		{"BTC-USDT", 101, ""},
		{"", 0, "bad token"},
		{"", 0, "\n"},
		{"", 0, strings.Repeat("a", 4097)},
	} {
		if err := OpenOrdersQuery(tc.market, tc.page, tc.token); !errors.Is(err, ErrInvalidField) {
			t.Errorf("invalid %+v: %v", tc, err)
		}
	}
}
