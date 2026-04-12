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

// IPAddressFilter identifies IPv4 and IPv6 addresses in text.
type IPAddressFilter struct {
	BaseRegexFilter
}

// NewIPAddressFilter creates a new IPAddressFilter.
func NewIPAddressFilter(strategies []policy.FilterStrategy, ignored []string, ignoredPatterns []policy.IgnoredPattern) *IPAddressFilter {
	patterns := []FilterPattern{
		{
			// IPv4
			Pattern:     regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`),
			Confidence:  0.90,
			GroupNumber: 0,
		},
		{
			// IPv6 standard full form: 8 groups of 4 hex digits separated by colons
			Pattern:     regexp.MustCompile(`(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}`),
			Confidence:  0.90,
			GroupNumber: 0,
		},
		{
			// IPv6 compressed form with ::
			Pattern:     regexp.MustCompile(`(?:[0-9a-fA-F]{1,4}:)*::(?:[0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{0,4}`),
			Confidence:  0.90,
			GroupNumber: 0,
		},
	}

	return &IPAddressFilter{
		BaseRegexFilter: NewBaseRegexFilter(model.FilterTypeIPAddress, patterns, strategies, ignored, ignoredPatterns),
	}
}

// Filter finds IP address spans in the input text.
func (f *IPAddressFilter) Filter(pol *policy.Policy, context string, input string) ([]model.Span, error) {
	if pol != nil && pol.Identifiers.IPAddress == nil {
		return nil, nil
	}

	spans, err := f.findSpans(pol, input, context)
	if err != nil {
		return nil, err
	}

	return model.DropOverlappingSpans(spans), nil
}
