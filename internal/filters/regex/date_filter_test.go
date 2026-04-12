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
	"testing"

	"github.com/philterd/go-philter/internal/policy"
	"github.com/stretchr/testify/assert"
)

func TestDateFilter_Filter(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "Month Day Year",
			input:    "The date is January 15, 2020.",
			expected: []string{"January 15, 2020"},
		},
		{
			name:     "Abbreviated Month Day Year",
			input:    "The date is Jan 15, 2020.",
			expected: []string{"Jan 15, 2020"},
		},
		{
			name:     "MM/DD/YYYY",
			input:    "The date is 01/15/2020.",
			expected: []string{"01/15/2020"},
		},
		{
			name:     "MM-DD-YYYY",
			input:    "The date is 01-15-2020.",
			expected: []string{"01-15-2020"},
		},
		{
			name:     "MM.DD.YYYY",
			input:    "The date is 01.15.2020.",
			expected: []string{"01.15.2020"},
		},
		{
			name:     "ISO 8601 YYYY-MM-DD",
			input:    "The date is 2020-01-15.",
			expected: []string{"2020-01-15"},
		},
		{
			name:     "DD Month YYYY",
			input:    "The date is 15 January 2020.",
			expected: []string{"15 January 2020"},
		},
		{
			name:     "Multiple dates",
			input:    "From 2020-01-15 to 2020-02-15.",
			expected: []string{"2020-01-15", "2020-02-15"},
		},
		{
			name:     "False positive - just year",
			input:    "In 2024 it happened.",
			expected: []string{},
		},
	}

	filter := NewDateFilter(nil, nil, nil)
	pol := &policy.Policy{
		Identifiers: policy.Identifiers{
			Date: &policy.DateFilter{
				BaseFilter: policy.BaseFilter{
					Enabled: new(true),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spans, err := filter.Filter(pol, "context", tt.input)
			assert.NoError(t, err)

			var actual []string
			for _, span := range spans {
				actual = append(actual, span.Text)
			}

			assert.ElementsMatch(t, tt.expected, actual)
		})
	}
}

func TestDateFilter_Disabled(t *testing.T) {
	filter := NewDateFilter(nil, nil, nil)
	pol := &policy.Policy{
		Identifiers: policy.Identifiers{
			Date: nil,
		},
	}

	input := "The date is January 15, 2020."
	spans, err := filter.Filter(pol, "context", input)

	assert.NoError(t, err)
	assert.Empty(t, spans)
}
