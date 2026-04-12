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

// TrackingNumberFilter identifies package tracking numbers from UPS, FedEx, and USPS.
type TrackingNumberFilter struct {
	BaseRegexFilter
}

// NewTrackingNumberFilter creates a new TrackingNumberFilter.
func NewTrackingNumberFilter(strategies []policy.FilterStrategy, ignored []string, ignoredPatterns []policy.IgnoredPattern) *TrackingNumberFilter {
	patterns := []FilterPattern{
		{
			// UPS tracking number: 1Z followed by 16 alphanumeric characters
			Pattern:     regexp.MustCompile(`(?i)\b1Z[A-Z0-9]{16}\b`),
			Confidence:  0.90,
			GroupNumber: 0,
		},
		{
			// FedEx tracking number: 12 or 15 digits, or 20 digits (Ground)
			Pattern:     regexp.MustCompile(`\b(?:\d{12}|\d{15}|\d{20})\b`),
			Confidence:  0.70,
			GroupNumber: 0,
		},
		{
			// USPS tracking number: 20-22 digits or various formats
			Pattern:     regexp.MustCompile(`\b\d{20,22}\b`),
			Confidence:  0.75,
			GroupNumber: 0,
		},
		{
			// USPS Priority Mail Express: EA/EB/EC/ED + 8 digits + US
			Pattern:     regexp.MustCompile(`(?i)\b[A-Z]{2}\d{8}US\b`),
			Confidence:  0.90,
			GroupNumber: 0,
		},
	}

	return &TrackingNumberFilter{
		BaseRegexFilter: NewBaseRegexFilter(model.FilterTypeTrackingNumber, patterns, strategies, ignored, ignoredPatterns),
	}
}

// Filter finds tracking number spans in the input text.
func (f *TrackingNumberFilter) Filter(pol *policy.Policy, context string, input string) ([]model.Span, error) {
	if pol != nil && pol.Identifiers.TrackingNumber == nil {
		return nil, nil
	}

	spans, err := f.findSpans(pol, input, context)
	if err != nil {
		return nil, err
	}

	return model.DropOverlappingSpans(spans), nil
}
