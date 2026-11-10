package validation

import (
	"errors"
	"strings"
	"testing"
)

func TestDecimalSyntax(t *testing.T) {
	valid := []string{"0", "0.0", "0.0000", "1", "10", "100.0", "0.000000000000000000001", "100000000000000000000000000000000000000000000000", "1.2300", "1" + strings.Repeat("2", 127)}
	for _, s := range valid {
		if err := Decimal(s); err != nil {
			t.Errorf("valid %q rejected: %v", s, err)
		}
	}
	invalid := []string{"", " ", " 1", "1 ", "+1", "-1", ".5", "1.", "1..2", "01", "00", "01.25", "1e9", "1E-2", "NaN", "Infinity", "1,000", "1_000", "1/2", "0x01", "１２.３", "1\n", "1\x00", "1" + strings.Repeat("2", 128)}
	for _, s := range invalid {
		if err := Decimal(s); !errors.Is(err, ErrInvalidDecimal) {
			t.Errorf("invalid %q accepted: %v", s, err)
		}
	}
}

func TestPositiveDecimalAndZero(t *testing.T) {
	for _, s := range []string{"1", "0.00001", "100000000000000000000000000000", "1.000", "9.9"} {
		if err := PositiveDecimal(s); err != nil {
			t.Errorf("positive %q: %v", s, err)
		}
	}
	for _, s := range []string{"0", "0.0", "0.00000"} {
		if err := PositiveDecimal(s); !errors.Is(err, ErrNonPositiveDecimal) {
			t.Errorf("zero %q: %v", s, err)
		}
	}
	if !errors.Is(PositiveDecimal("-0"), ErrInvalidDecimal) {
		t.Fatal("negative zero must be rejected syntactically")
	}
}

func FuzzPositiveDecimal(f *testing.F) {
	for _, seed := range []string{"1.00", "0.000001", "0", "1e5", ".1", "01", "٣", strings.Repeat("9", 129)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if PositiveDecimal(input) == nil {
			if len(input) == 0 || len(input) > MaxDecimalLength || input[0] == '0' && len(input) == 1 {
				t.Fatalf("accepted invalid positive decimal %q", input)
			}
			if err := Decimal(input); err != nil {
				t.Fatalf("positive passed but syntax failed: %q", input)
			}
		}
	})
}
