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

// URLFilter identifies URLs in text.
type URLFilter struct {
	BaseRegexFilter
}

// NewURLFilter creates a new URLFilter.
// When requireHTTPWWWPrefix is true, only URLs with http://, https://, or www. prefix are matched.
func NewURLFilter(strategies []policy.FilterStrategy, ignored []string, ignoredPatterns []policy.IgnoredPattern, requireHTTPWWWPrefix bool) *URLFilter {
	var patterns []FilterPattern

	if requireHTTPWWWPrefix {
		patterns = []FilterPattern{
			{
				// URLs with required http/https/www prefix
				Pattern:     regexp.MustCompile(`(?i)(www\.|http://www\.|https://www\.|http://|https://)[a-z\d]+([\-\.]{1}[a-z\d]+)*\.[a-z]{2,5}(:[0-9]{1,5})?(\/.*)?`),
				Confidence:  0.80,
				GroupNumber: 0,
			},
		}
	} else {
		patterns = []FilterPattern{
			{
				// URLs with optional protocol
				Pattern:     regexp.MustCompile(`(?i)(http://www\.|https://www\.|http://|https://)?[a-z\d]+([\-\.]{1}[a-z\d]+)*\.[a-z]{2,5}(:[0-9]{1,5})?(\/.*)?`),
				Confidence:  0.10,
				GroupNumber: 0,
			},
		}
	}

	return &URLFilter{
		BaseRegexFilter: NewBaseRegexFilter(model.FilterTypeURL, patterns, strategies, ignored, ignoredPatterns),
	}
}

// Filter finds URL spans in the input text.
func (f *URLFilter) Filter(pol *policy.Policy, context string, input string) ([]model.Span, error) {
	if pol != nil && pol.Identifiers.URL == nil {
		return nil, nil
	}

	spans, err := f.findSpans(pol, input, context)
	if err != nil {
		return nil, err
	}

	return model.DropOverlappingSpans(spans), nil
}
