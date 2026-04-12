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
	"strings"

	"github.com/philterd/go-philter/internal/model"
	"github.com/philterd/go-philter/internal/policy"
)

// AgeFilter identifies ages in text (e.g., "45 years old", "aged 30", "61 y/o").
type AgeFilter struct {
	BaseRegexFilter
}

// NewAgeFilter creates a new AgeFilter.
func NewAgeFilter(strategies []policy.FilterStrategy, ignored []string, ignoredPatterns []policy.IgnoredPattern) *AgeFilter {
	patterns := []FilterPattern{
		{
			Pattern:     regexp.MustCompile(`(?i)\b[0-9.]+[\s]*(year|years|yrs|yr|yo)(.?)(\s)*(old)?\b`),
			Confidence:  0.90,
			GroupNumber: 0,
		},
		{
			Pattern:     regexp.MustCompile(`(?i)\b(age)(d)?(\s)*[0-9.]+\b`),
			Confidence:  0.90,
			GroupNumber: 0,
		},
		{
			Pattern:     regexp.MustCompile(`(?i)\b[0-9.]+[-]*(year|years|yrs|yr|yo)[-. ]*(?:old)?\b`),
			Confidence:  0.90,
			GroupNumber: 0,
		},
		{
			// 61 y/o
			Pattern:     regexp.MustCompile(`(?i)\b([0-9]{1,3}) (y\/o)\b`),
			Confidence:  0.90,
			GroupNumber: 0,
		},
	}

	return &AgeFilter{
		BaseRegexFilter: NewBaseRegexFilter(model.FilterTypeAge, patterns, strategies, ignored, ignoredPatterns),
	}
}

// Filter finds age spans in the input text.
func (f *AgeFilter) Filter(pol *policy.Policy, context string, input string) ([]model.Span, error) {
	if pol != nil && pol.Identifiers.Age == nil {
		return nil, nil
	}

	spans, err := f.findSpans(pol, input, context)
	if err != nil {
		return nil, err
	}

	// Post-filter: only keep spans that contain age-related terms.
	var filtered []model.Span
	for _, span := range spans {
		lower := strings.ToLower(span.Text)
		if strings.Contains(lower, "age") ||
			strings.Contains(lower, "aged") ||
			strings.Contains(lower, "old") ||
			strings.Contains(lower, "y/o") ||
			strings.Contains(lower, "yo") {
			filtered = append(filtered, span)
		}
	}

	return model.DropOverlappingSpans(filtered), nil
}
