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

// PassportNumberFilter identifies US passport numbers in text.
type PassportNumberFilter struct {
	BaseRegexFilter
}

// NewPassportNumberFilter creates a new PassportNumberFilter.
func NewPassportNumberFilter(strategies []policy.FilterStrategy, ignored []string, ignoredPatterns []policy.IgnoredPattern) *PassportNumberFilter {
	patterns := []FilterPattern{
		{
			// US Passport: one letter followed by 8 digits
			Pattern:     regexp.MustCompile(`(?i)\b[A-Z][0-9]{8}\b`),
			Confidence:  0.75,
			GroupNumber: 0,
		},
	}

	return &PassportNumberFilter{
		BaseRegexFilter: NewBaseRegexFilter(model.FilterTypePassportNumber, patterns, strategies, ignored, ignoredPatterns),
	}
}

// Filter finds passport number spans in the input text.
func (f *PassportNumberFilter) Filter(pol *policy.Policy, context string, input string) ([]model.Span, error) {
	if pol != nil && pol.Identifiers.PassportNumber == nil {
		return nil, nil
	}

	return f.findSpans(pol, input, context)
}
