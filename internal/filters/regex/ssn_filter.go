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

// SSNFilter identifies Social Security Numbers and Taxpayer Identification Numbers in text.
type SSNFilter struct {
	BaseRegexFilter
}

// NewSSNFilter creates a new SSNFilter.
func NewSSNFilter(strategies []policy.FilterStrategy, ignored []string, ignoredPatterns []policy.IgnoredPattern) *SSNFilter {
	patterns := []FilterPattern{
		{
			// SSN: 9 digits optionally separated by dashes or spaces.
			// Go's regexp does not support lookaheads, so invalid prefixes (000, 666, 900-999)
			// are filtered in the post-processing step.
			Pattern:     regexp.MustCompile(`\b[0-9]{3}[- ]?[0-9]{2}[- ]?[0-9]{4}\b`),
			Confidence:  0.90,
			GroupNumber: 0,
		},
		{
			// TIN: ##-#######
			Pattern:     regexp.MustCompile(`\b[0-9]{2}-[0-9]{7}\b`),
			Confidence:  0.90,
			GroupNumber: 0,
		},
	}

	return &SSNFilter{
		BaseRegexFilter: NewBaseRegexFilter(model.FilterTypeSSN, patterns, strategies, ignored, ignoredPatterns),
	}
}

// isInvalidSSNPrefix returns true if the SSN prefix is known to be invalid.
func isInvalidSSNPrefix(ssn string) bool {
	// Remove dashes and spaces to get raw digits
	raw := regexp.MustCompile(`[- ]`).ReplaceAllString(ssn, "")
	if len(raw) < 3 {
		return false
	}
	prefix := raw[:3]
	// Invalid prefixes: 000, 666, 900-999
	if prefix == "000" || prefix == "666" {
		return true
	}
	if prefix[0] == '9' {
		return true
	}
	return false
}

// Filter finds SSN/TIN spans in the input text.
func (f *SSNFilter) Filter(pol *policy.Policy, context string, input string) ([]model.Span, error) {
	if pol != nil && pol.Identifiers.SSN == nil {
		return nil, nil
	}

	spans, err := f.findSpans(pol, input, context)
	if err != nil {
		return nil, err
	}

	// Post-filter: remove SSNs with known invalid prefixes.
	var filtered []model.Span
	for _, span := range spans {
		// Only apply prefix validation for SSN pattern (9 digits), not TIN (which has dash after 2 digits)
		if regexp.MustCompile(`^\d{2}-`).MatchString(span.Text) {
			// TIN format - keep as-is
			filtered = append(filtered, span)
		} else if !isInvalidSSNPrefix(span.Text) {
			filtered = append(filtered, span)
		}
	}

	return filtered, nil
}
