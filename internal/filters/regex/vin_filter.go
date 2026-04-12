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

// VINFilter identifies Vehicle Identification Numbers (VINs) in text.
type VINFilter struct {
	BaseRegexFilter
}

// NewVINFilter creates a new VINFilter.
func NewVINFilter(strategies []policy.FilterStrategy, ignored []string, ignoredPatterns []policy.IgnoredPattern) *VINFilter {
	patterns := []FilterPattern{
		{
			// VIN: 17 alphanumeric characters, excluding I, O, Q to avoid confusion with 1, 0
			Pattern:     regexp.MustCompile(`(?i)\b[A-HJ-NPR-Z0-9]{17}\b`),
			Confidence:  0.90,
			GroupNumber: 0,
		},
	}

	return &VINFilter{
		BaseRegexFilter: NewBaseRegexFilter(model.FilterTypeVIN, patterns, strategies, ignored, ignoredPatterns),
	}
}

// Filter finds VIN spans in the input text.
func (f *VINFilter) Filter(pol *policy.Policy, context string, input string) ([]model.Span, error) {
	if pol != nil && pol.Identifiers.VIN == nil {
		return nil, nil
	}

	return f.findSpans(pol, input, context)
}
