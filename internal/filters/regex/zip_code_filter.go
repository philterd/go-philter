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

// ZipCodeFilter identifies US ZIP codes in text.
type ZipCodeFilter struct {
	BaseRegexFilter
}

// NewZipCodeFilter creates a new ZipCodeFilter.
// When requireDelimiter is true, ZIP+4 codes must have a dash separator (e.g., 12345-6789).
func NewZipCodeFilter(strategies []policy.FilterStrategy, ignored []string, ignoredPatterns []policy.IgnoredPattern, requireDelimiter bool) *ZipCodeFilter {
	var pattern *regexp.Regexp
	if requireDelimiter {
		pattern = regexp.MustCompile(`\b[0-9]{5}(?:-[0-9]{4})?\b`)
	} else {
		pattern = regexp.MustCompile(`\b[0-9]{5}(?:-?[0-9]{4})?\b`)
	}

	confidence := 0.90
	if !requireDelimiter {
		confidence = 0.50
	}

	patterns := []FilterPattern{
		{
			Pattern:     pattern,
			Confidence:  confidence,
			GroupNumber: 0,
		},
	}

	return &ZipCodeFilter{
		BaseRegexFilter: NewBaseRegexFilter(model.FilterTypeZipCode, patterns, strategies, ignored, ignoredPatterns),
	}
}

// Filter finds ZIP code spans in the input text.
func (f *ZipCodeFilter) Filter(pol *policy.Policy, context string, input string) ([]model.Span, error) {
	if pol != nil && pol.Identifiers.ZipCode == nil {
		return nil, nil
	}

	return f.findSpans(pol, input, context)
}
