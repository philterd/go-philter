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

// PhoneNumberFilter identifies US phone numbers in text.
type PhoneNumberFilter struct {
	BaseRegexFilter
}

// NewPhoneNumberFilter creates a new PhoneNumberFilter.
func NewPhoneNumberFilter(strategies []policy.FilterStrategy, ignored []string, ignoredPatterns []policy.IgnoredPattern) *PhoneNumberFilter {
	patterns := []FilterPattern{
		{
			// US phone number: (###) ###-#### or ###-###-#### or ###.###.####
			// The optional country code +1 or 1 is included.
			Pattern:     regexp.MustCompile(`(?:(?:\+?1[-. ]?)?\(?\d{3}\)?[-. ]?\d{3}[-. ]?\d{4})`),
			Confidence:  0.90,
			GroupNumber: 0,
		},
		{
			// International format: starts with + followed by country code and number
			Pattern:     regexp.MustCompile(`\+\d{1,3}[-. ]?\(?\d{1,4}\)?[-. ]?\d{1,4}[-. ]?\d{1,9}`),
			Confidence:  0.85,
			GroupNumber: 0,
		},
	}

	return &PhoneNumberFilter{
		BaseRegexFilter: NewBaseRegexFilter(model.FilterTypePhoneNumber, patterns, strategies, ignored, ignoredPatterns),
	}
}

// Filter finds phone number spans in the input text.
func (f *PhoneNumberFilter) Filter(pol *policy.Policy, context string, input string) ([]model.Span, error) {
	if pol != nil && pol.Identifiers.PhoneNumber == nil {
		return nil, nil
	}

	spans, err := f.findSpans(pol, input, context)
	if err != nil {
		return nil, err
	}

	return model.DropOverlappingSpans(spans), nil
}
