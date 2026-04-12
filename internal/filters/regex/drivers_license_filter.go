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

// DriverLicenseFilter identifies US driver's license numbers in text.
type DriverLicenseFilter struct {
	BaseRegexFilter
}

// NewDriverLicenseFilter creates a new DriverLicenseFilter.
func NewDriverLicenseFilter(strategies []policy.FilterStrategy, ignored []string, ignoredPatterns []policy.IgnoredPattern) *DriverLicenseFilter {
	patterns := []FilterPattern{
		{
			// Generic US driver's license: letters and numbers, 8-12 chars
			Pattern:     regexp.MustCompile(`(?i)\b[a-z]\d{7}\b`),
			Confidence:  0.70,
			GroupNumber: 0,
		},
		{
			// All-numeric driver's license: 7-9 digits
			Pattern:     regexp.MustCompile(`\b\d{7,9}\b`),
			Confidence:  0.50,
			GroupNumber: 0,
		},
		{
			// Alphanumeric: letter + digits (common format)
			Pattern:     regexp.MustCompile(`(?i)\b[a-z]{1,2}\d{5,7}\b`),
			Confidence:  0.70,
			GroupNumber: 0,
		},
	}

	return &DriverLicenseFilter{
		BaseRegexFilter: NewBaseRegexFilter(model.FilterTypeDriversLicense, patterns, strategies, ignored, ignoredPatterns),
	}
}

// Filter finds driver's license number spans in the input text.
func (f *DriverLicenseFilter) Filter(pol *policy.Policy, context string, input string) ([]model.Span, error) {
	if pol != nil && pol.Identifiers.DriversLicense == nil {
		return nil, nil
	}

	spans, err := f.findSpans(pol, input, context)
	if err != nil {
		return nil, err
	}

	return model.DropOverlappingSpans(spans), nil
}
