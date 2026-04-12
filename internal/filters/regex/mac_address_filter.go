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

// MACAddressFilter identifies MAC addresses in text.
type MACAddressFilter struct {
	BaseRegexFilter
}

// NewMACAddressFilter creates a new MACAddressFilter.
func NewMACAddressFilter(strategies []policy.FilterStrategy, ignored []string, ignoredPatterns []policy.IgnoredPattern) *MACAddressFilter {
	patterns := []FilterPattern{
		{
			// MAC address with colons or dashes: XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX
			Pattern:     regexp.MustCompile(`(?i)\b(?:[0-9a-f]{2}[:\-]){5}[0-9a-f]{2}\b`),
			Confidence:  0.90,
			GroupNumber: 0,
		},
		{
			// MAC address with dots: XXXX.XXXX.XXXX (Cisco format)
			Pattern:     regexp.MustCompile(`(?i)\b(?:[0-9a-f]{4}\.){2}[0-9a-f]{4}\b`),
			Confidence:  0.90,
			GroupNumber: 0,
		},
	}

	return &MACAddressFilter{
		BaseRegexFilter: NewBaseRegexFilter(model.FilterTypeMACAddress, patterns, strategies, ignored, ignoredPatterns),
	}
}

// Filter finds MAC address spans in the input text.
func (f *MACAddressFilter) Filter(pol *policy.Policy, context string, input string) ([]model.Span, error) {
	if pol != nil && pol.Identifiers.MACAddress == nil {
		return nil, nil
	}

	return f.findSpans(pol, input, context)
}
