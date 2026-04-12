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

// BankRoutingNumberFilter identifies US bank routing numbers in text.
type BankRoutingNumberFilter struct {
	BaseRegexFilter
}

// NewBankRoutingNumberFilter creates a new BankRoutingNumberFilter.
func NewBankRoutingNumberFilter(strategies []policy.FilterStrategy, ignored []string, ignoredPatterns []policy.IgnoredPattern) *BankRoutingNumberFilter {
	patterns := []FilterPattern{
		{
			// US Bank Routing Number: 9 digits, first digit 0-1, 2, 3, 6, or 7
			Pattern:     regexp.MustCompile(`\b[0123679]\d{8}\b`),
			Confidence:  0.75,
			GroupNumber: 0,
		},
	}

	return &BankRoutingNumberFilter{
		BaseRegexFilter: NewBaseRegexFilter(model.FilterTypeBankRoutingNumber, patterns, strategies, ignored, ignoredPatterns),
	}
}

// Filter finds bank routing number spans in the input text.
func (f *BankRoutingNumberFilter) Filter(pol *policy.Policy, context string, input string) ([]model.Span, error) {
	if pol != nil && pol.Identifiers.BankRoutingNumber == nil {
		return nil, nil
	}

	return f.findSpans(pol, input, context)
}
