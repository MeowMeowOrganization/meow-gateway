// Package validation performs edge-only syntactic checks. Market-specific
// scales, tick/lot sizes, balances and trading policies belong to Order Service.
package validation

import "errors"

const MaxDecimalLength = 128

var (
	ErrInvalidDecimal     = errors.New("invalid decimal syntax")
	ErrNonPositiveDecimal = errors.New("decimal must be greater than zero")
)

// Decimal checks a strictly formatted, non-negative base-10 decimal string.
// Syntax: (0|[1-9][0-9]*)(.[0-9]+)? (the dot is literal).
// Signs, exponent notation, whitespace, leading zeros and non-ASCII digits
// are forbidden. Trailing fractional zeros are allowed; the Order Service
// owns economic normalization and market precision rules. No float conversion.
func Decimal(value string) error {
	_, err := scanDecimal(value)
	return err
}

// PositiveDecimal is intended for price and quantity edge checks. It rejects
// any representation of zero without converting to integers or floats.
func PositiveDecimal(value string) error {
	positive, err := scanDecimal(value)
	if err != nil {
		return err
	}
	if !positive {
		return ErrNonPositiveDecimal
	}
	return nil
}

func scanDecimal(value string) (bool, error) {
	if len(value) == 0 || len(value) > MaxDecimalLength {
		return false, ErrInvalidDecimal
	}
	seenPoint := false
	fractionDigits := 0
	positive := false
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c == '.' {
			if seenPoint || i == 0 {
				return false, ErrInvalidDecimal
			}
			seenPoint = true
			continue
		}
		if c < '0' || c > '9' {
			return false, ErrInvalidDecimal
		}
		if i == 1 && value[0] == '0' && !seenPoint {
			return false, ErrInvalidDecimal
		}
		if seenPoint {
			fractionDigits++
		}
		positive = positive || c != '0'
	}
	if seenPoint && fractionDigits == 0 {
		return false, ErrInvalidDecimal
	}
	return positive, nil
}
