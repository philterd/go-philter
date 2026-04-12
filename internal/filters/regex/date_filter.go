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

// DateFilter identifies dates in text.
type DateFilter struct {
	BaseRegexFilter
}

// NewDateFilter creates a new DateFilter.
func NewDateFilter(strategies []policy.FilterStrategy, ignored []string, ignoredPatterns []policy.IgnoredPattern) *DateFilter {
	patterns := []FilterPattern{
		{
			// Month name, day, year (e.g., "January 15, 2020" or "Jan 15, 2020")
			Pattern:     regexp.MustCompile(`(?i)\b(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\s+\d{1,2},?\s+\d{4}\b`),
			Confidence:  0.90,
			GroupNumber: 0,
		},
		{
			// MM/DD/YYYY or MM-DD-YYYY or MM.DD.YYYY
			Pattern:     regexp.MustCompile(`\b(?:0?[1-9]|1[0-2])[/\-.](?:0?[1-9]|[12][0-9]|3[01])[/\-.](?:19|20)\d{2}\b`),
			Confidence:  0.80,
			GroupNumber: 0,
		},
		{
			// YYYY-MM-DD (ISO 8601)
			Pattern:     regexp.MustCompile(`\b(?:19|20)\d{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])\b`),
			Confidence:  0.90,
			GroupNumber: 0,
		},
		{
			// DD Month YYYY (e.g., "15 January 2020")
			Pattern:     regexp.MustCompile(`(?i)\b\d{1,2}\s+(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\s+\d{4}\b`),
			Confidence:  0.85,
			GroupNumber: 0,
		},
	}

	return &DateFilter{
		BaseRegexFilter: NewBaseRegexFilter(model.FilterTypeDate, patterns, strategies, ignored, ignoredPatterns),
	}
}

// Filter finds date spans in the input text.
func (f *DateFilter) Filter(pol *policy.Policy, context string, input string) ([]model.Span, error) {
	if pol != nil && pol.Identifiers.Date == nil {
		return nil, nil
	}

	spans, err := f.findSpans(pol, input, context)
	if err != nil {
		return nil, err
	}

	return model.DropOverlappingSpans(spans), nil
}
