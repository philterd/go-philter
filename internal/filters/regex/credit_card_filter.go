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

package regex

import (
	"regexp"

	"github.com/philterd/go-philter/internal/model"
	"github.com/philterd/go-philter/internal/policy"
)

// luhnCheck returns true if the digits in s pass the Luhn algorithm.
// Non-digit characters are ignored.
func luhnCheck(s string) bool {
	sum := 0
	nDigits := 0
	for i := len(s) - 1; i >= 0; i-- {
		c := s[i]
		if c < '0' || c > '9' {
			continue
		}
		digit := int(c - '0')
		if nDigits%2 == 1 {
			digit *= 2
			if digit > 9 {
				digit -= 9
			}
		}
		sum += digit
		nDigits++
	}
	return nDigits > 0 && sum%10 == 0
}

// CreditCardFilter identifies credit card numbers in text.
type CreditCardFilter struct {
	BaseRegexFilter
}

// NewCreditCardFilter creates a new CreditCardFilter.
func NewCreditCardFilter(strategies []policy.FilterStrategy, ignored []string, ignoredPatterns []policy.IgnoredPattern) *CreditCardFilter {
	patterns := []FilterPattern{
		{
			// Visa: starts with 4, 13 or 16 digits
			Pattern:     regexp.MustCompile(`\b4[0-9]{12}(?:[0-9]{3})?\b`),
			Confidence:  0.90,
			GroupNumber: 0,
		},
		{
			// MasterCard: starts with 51-55 or 2221-2720, 16 digits
			Pattern:     regexp.MustCompile(`\b(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12}\b`),
			Confidence:  0.90,
			GroupNumber: 0,
		},
		{
			// American Express: starts with 34 or 37, 15 digits
			Pattern:     regexp.MustCompile(`\b3[47][0-9]{13}\b`),
			Confidence:  0.90,
			GroupNumber: 0,
		},
		{
			// Diners Club: starts with 300-305, 36, or 38, 14 digits
			Pattern:     regexp.MustCompile(`\b3(?:0[0-5]|[68][0-9])[0-9]{11}\b`),
			Confidence:  0.90,
			GroupNumber: 0,
		},
		{
			// Discover: starts with 6011 or 65, 16 digits
			Pattern:     regexp.MustCompile(`\b6(?:011|5[0-9]{2})[0-9]{12}\b`),
			Confidence:  0.90,
			GroupNumber: 0,
		},
		{
			// JCB: starts with 2131, 1800, or 35, 15-16 digits
			Pattern:     regexp.MustCompile(`\b(?:2131|1800|35\d{3})\d{11}\b`),
			Confidence:  0.90,
			GroupNumber: 0,
		},
	}

	return &CreditCardFilter{
		BaseRegexFilter: NewBaseRegexFilter(model.FilterTypeCreditCard, patterns, strategies, ignored, ignoredPatterns),
	}
}

// Filter finds credit card number spans in the input text.
func (f *CreditCardFilter) Filter(pol *policy.Policy, context string, input string) ([]model.Span, error) {
	if pol != nil && pol.Identifiers.CreditCard == nil {
		return nil, nil
	}

	spans, err := f.findSpans(pol, input, context)
	if err != nil {
		return nil, err
	}

	if pol != nil && pol.Identifiers.CreditCard != nil && pol.Identifiers.CreditCard.OnlyValidCreditCardNumbers {
		valid := make([]model.Span, 0, len(spans))
		for _, span := range spans {
			if luhnCheck(span.Text) {
				valid = append(valid, span)
			}
		}
		spans = valid
	}

	return model.DropOverlappingSpans(spans), nil
}
