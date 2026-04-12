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

// BitcoinAddressFilter identifies Bitcoin addresses in text.
type BitcoinAddressFilter struct {
	BaseRegexFilter
}

// NewBitcoinAddressFilter creates a new BitcoinAddressFilter.
func NewBitcoinAddressFilter(strategies []policy.FilterStrategy, ignored []string, ignoredPatterns []policy.IgnoredPattern) *BitcoinAddressFilter {
	patterns := []FilterPattern{
		{
			// Legacy Bitcoin addresses (P2PKH and P2SH): start with 1 or 3, 25-34 chars
			Pattern:     regexp.MustCompile(`\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b`),
			Confidence:  0.90,
			GroupNumber: 0,
		},
		{
			// Bech32 Bitcoin addresses (P2WPKH): start with bc1
			Pattern:     regexp.MustCompile(`\bbc1[ac-hj-np-z02-9]{6,87}\b`),
			Confidence:  0.90,
			GroupNumber: 0,
		},
	}

	return &BitcoinAddressFilter{
		BaseRegexFilter: NewBaseRegexFilter(model.FilterTypeBitcoinAddress, patterns, strategies, ignored, ignoredPatterns),
	}
}

// Filter finds Bitcoin address spans in the input text.
func (f *BitcoinAddressFilter) Filter(pol *policy.Policy, context string, input string) ([]model.Span, error) {
	if pol != nil && pol.Identifiers.BitcoinAddress == nil {
		return nil, nil
	}

	return f.findSpans(pol, input, context)
}
