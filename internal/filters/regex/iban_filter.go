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

// IBANFilter identifies International Bank Account Numbers (IBANs) in text.
type IBANFilter struct {
	BaseRegexFilter
}

// NewIBANFilter creates a new IBANFilter.
func NewIBANFilter(strategies []policy.FilterStrategy, ignored []string, ignoredPatterns []policy.IgnoredPattern) *IBANFilter {
	patterns := []FilterPattern{
		{
			// IBAN: 2-letter country code + 2 check digits + up to 30 alphanumeric chars
			Pattern:     regexp.MustCompile(`(?i)\b[A-Z]{2}[0-9]{2}[A-Z0-9]{1,30}\b`),
			Confidence:  0.85,
			GroupNumber: 0,
		},
	}

	return &IBANFilter{
		BaseRegexFilter: NewBaseRegexFilter(model.FilterTypeIbanCode, patterns, strategies, ignored, ignoredPatterns),
	}
}

// Filter finds IBAN spans in the input text.
func (f *IBANFilter) Filter(pol *policy.Policy, context string, input string) ([]model.Span, error) {
	if pol != nil && pol.Identifiers.IbanCode == nil {
		return nil, nil
	}

	return f.findSpans(pol, input, context)
}
