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

// EmailAddressFilter identifies email addresses in text.
type EmailAddressFilter struct {
	BaseRegexFilter
}

// NewEmailAddressFilter creates a new EmailAddressFilter.
// When onlyStrictMatches is true, a more strict RFC 5321 compliant regex is used.
func NewEmailAddressFilter(strategies []policy.FilterStrategy, ignored []string, ignoredPatterns []policy.IgnoredPattern, onlyStrictMatches bool) *EmailAddressFilter {
	var pattern *regexp.Regexp
	if onlyStrictMatches {
		pattern = regexp.MustCompile(`(?i)\b(?:[a-z\d!#$%&'*+/=?^_` + "`" + `{|}~-]+(?:\.[a-z\d!#$%&'*+/=?^_` + "`" + `{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z\d](?:[a-z\d-]*[a-z\d])?\.)+[a-z\d](?:[a-z\d-]*[a-z\d])?|\[(?:(?:25[0-5]|2[0-4][\d]|[01]?[\d][\d]?)\.){3}(?:25[0-5]|2[0-4][\d]|[01]?[\d][\d]?|[a-z\d-]*[a-z\d]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])\b`)
	} else {
		// General email pattern supporting common characters including +
		pattern = regexp.MustCompile(`(?i)\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b`)
	}

	patterns := []FilterPattern{
		{
			Pattern:     pattern,
			Confidence:  0.90,
			GroupNumber: 0,
		},
	}

	return &EmailAddressFilter{
		BaseRegexFilter: NewBaseRegexFilter(model.FilterTypeEmailAddress, patterns, strategies, ignored, ignoredPatterns),
	}
}

// Filter finds email address spans in the input text.
func (f *EmailAddressFilter) Filter(pol *policy.Policy, context string, input string) ([]model.Span, error) {
	if pol != nil && pol.Identifiers.EmailAddress == nil {
		return nil, nil
	}

	return f.findSpans(pol, input, context)
}
