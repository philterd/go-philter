// Copyright 2026 Philterd, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package filters

import (
	"regexp"
	"strings"
	"testing"

	"github.com/philterd/go-philter/internal/model"
)

func TestRandomReplaceForType(t *testing.T) {
	tests := []struct {
		filterType model.FilterType
		pattern    *regexp.Regexp
	}{
		{model.FilterTypeSSN, regexp.MustCompile(`^\d{3}-\d{2}-\d{4}$`)},
		{model.FilterTypeEmailAddress, regexp.MustCompile(`^[a-z]+\d+@(example\.com|test\.org|sample\.net)$`)},
		{model.FilterTypePhoneNumber, regexp.MustCompile(`^\(555\) \d{3}-\d{4}$`)},
		{model.FilterTypePhoneNumberExt, regexp.MustCompile(`^\(555\) \d{3}-\d{4}$`)},
		{model.FilterTypeCreditCard, regexp.MustCompile(`^4\d{3}-\d{4}-\d{4}-\d{4}$`)},
		{model.FilterTypeIPAddress, regexp.MustCompile(`^192\.168\.\d{1,3}\.\d{1,3}$`)},
		{model.FilterTypeDate, regexp.MustCompile(`^\d{2}/\d{2}/\d{4}$`)},
		{model.FilterTypeZipCode, regexp.MustCompile(`^\d{5}$`)},
		{model.FilterTypeMACAddress, regexp.MustCompile(`^02:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$`)},
		{model.FilterTypeVIN, regexp.MustCompile(`^[A-Z0-9]{17}$`)},
		{model.FilterTypeBankRoutingNumber, regexp.MustCompile(`^\d{9}$`)},
		{model.FilterTypeBitcoinAddress, regexp.MustCompile(`^1[1-9A-HJ-NP-Za-km-z]{25,32}$`)},
		{model.FilterTypeAge, regexp.MustCompile(`^\d+ years old$`)},
		{model.FilterTypeURL, regexp.MustCompile(`^https://example\.com/[a-z]+\d+$`)},
		{model.FilterTypeIbanCode, regexp.MustCompile(`^GB\d{2}[A-Z]{4}\d{14}$`)},
		{model.FilterTypePassportNumber, regexp.MustCompile(`^[A-Z]\d{8}$`)},
		{model.FilterTypeDriversLicense, regexp.MustCompile(`^[A-Z]\d{7}$`)},
		{model.FilterTypeTrackingNumber, regexp.MustCompile(`^1Z\d{9}$`)},
	}

	context := "test-context"
	text := "sensitive-value"

	for _, tt := range tests {
		t.Run(string(tt.filterType), func(t *testing.T) {
			got := RandomReplaceForType(tt.filterType, text, context)
			if !tt.pattern.MatchString(got) {
				t.Errorf("RandomReplaceForType(%s) = %q, want format %s", tt.filterType, got, tt.pattern)
			}
		})
	}
}

func TestRandomReplaceForType_Determinism(t *testing.T) {
	filterType := model.FilterTypeSSN
	text := "123-45-6789"
	context := "context-1"

	res1 := RandomReplaceForType(filterType, text, context)
	res2 := RandomReplaceForType(filterType, text, context)

	if res1 != res2 {
		t.Errorf("RandomReplaceForType is not deterministic: %q != %q", res1, res2)
	}

	// Different context should produce different result
	res3 := RandomReplaceForType(filterType, text, "context-2")
	if res1 == res3 {
		t.Errorf("RandomReplaceForType produced same result for different context: %q == %q", res1, res3)
	}

	// Different text should produce different result
	res4 := RandomReplaceForType(filterType, "987-65-4321", context)
	if res1 == res4 {
		t.Errorf("RandomReplaceForType produced same result for different text: %q == %q", res1, res4)
	}
}

func TestRandomReplaceForType_Default(t *testing.T) {
	filterType := model.FilterType("UnknownType")
	got := RandomReplaceForType(filterType, "text", "context")
	want := "{{{REDACTED-UnknownType}}}"

	if got != want {
		t.Errorf("RandomReplaceForType(UnknownType) = %q, want %q", got, want)
	}
}

func TestRandomCreditCard_LuhnValid(t *testing.T) {
	// Generate several cards and verify each one
	context := "cc-test"
	for i := range 10 {
		text := string(rune('0' + i))
		cc := RandomReplaceForType(model.FilterTypeCreditCard, text, context)
		// Remove dashes
		cc = strings.ReplaceAll(cc, "-", "")

		if !isLuhnValid(cc) {
			t.Errorf("Generated credit card %s is not Luhn valid", cc)
		}
	}
}

func isLuhnValid(number string) bool {
	sum := 0
	nDigits := len(number)
	parity := nDigits % 2
	for i := 0; i < nDigits; i++ {
		digit := int(number[i] - '0')
		if i%2 == parity {
			digit *= 2
			if digit > 9 {
				digit -= 9
			}
		}
		sum += digit
	}
	return sum%10 == 0
}

func TestRandomSSN_ValidArea(t *testing.T) {
	context := "ssn-test"
	for i := range 100 {
		text := string(rune(i))
		ssn := RandomReplaceForType(model.FilterTypeSSN, text, context)
		parts := strings.Split(ssn, "-")
		area := parts[0]

		if area == "000" || area == "666" || area[0] == '9' {
			t.Errorf("Generated invalid SSN area: %s (full SSN: %s)", area, ssn)
		}
	}
}
