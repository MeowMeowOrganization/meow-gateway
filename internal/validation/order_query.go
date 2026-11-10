package validation

import (
	"fmt"
	"strconv"
)

// OrderID validates the canonical positive signed-BIGINT wire representation
// required by the private Order Service. Parsing an identifier as an integer
// does not affect price or quantity precision.
func OrderID(value string) error {
	if len(value) == 0 || len(value) > 19 || value[0] == '0' {
		return ErrInvalidField
	}
	for i := 0; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			return ErrInvalidField
		}
	}
	id, err := strconv.ParseInt(value, 10, 64)
	if err != nil || id <= 0 {
		return ErrInvalidField
	}
	return nil
}

// OpenOrdersQuery validates only public syntax and size limits. The backend
// verifies cursor scope, account ownership, and allowed market membership.
// The opaque page token is deliberately not decoded or rewritten here.
func OpenOrdersQuery(marketID string, pageSize int32, pageToken string) error {
	if marketID != "" {
		if err := Identifier(marketID); err != nil {
			return fmt.Errorf("market_id: %w", err)
		}
	}
	if pageSize < 0 || pageSize > 100 {
		return fmt.Errorf("page_size: %w", ErrInvalidField)
	}
	if len(pageToken) > 4096 {
		return fmt.Errorf("page_token: %w", ErrInvalidField)
	}
	for i := 0; i < len(pageToken); i++ {
		if pageToken[i] < '!' || pageToken[i] > '~' {
			return fmt.Errorf("page_token: %w", ErrInvalidField)
		}
	}
	return nil
}
