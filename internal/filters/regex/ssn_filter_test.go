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

func TestSSNFilter_Filter(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "Valid SSN with dashes",
			input:    "My SSN is 123-45-6789.",
			expected: []string{"123-45-6789"},
		},
		{
			name:     "Valid SSN with spaces",
			input:    "My SSN is 123 45 6789.",
			expected: []string{"123 45 6789"},
		},
		{
			name:     "Invalid SSN prefix 000",
			input:    "Invalid: 000-45-6789.",
			expected: []string{},
		},
		{
			name:     "Invalid SSN prefix 666",
			input:    "Invalid: 666-45-6789.",
			expected: []string{},
		},
		{
			name:     "Invalid SSN prefix 9xx",
			input:    "Invalid: 900-45-6789.",
			expected: []string{},
		},
		{
			name:     "Valid TIN",
			input:    "My TIN is 12-3456789.",
			expected: []string{"12-3456789"},
		},
	}

	filter := NewSSNFilter(nil, nil, nil)
	pol := &policy.Policy{
		Identifiers: policy.Identifiers{
			SSN: &policy.SSNFilter{
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

func TestSSNFilter_Disabled(t *testing.T) {
	filter := NewSSNFilter(nil, nil, nil)
	pol := &policy.Policy{
		Identifiers: policy.Identifiers{
			SSN: nil,
		},
	}

	input := "My SSN is 123-45-6789."
	spans, err := filter.Filter(pol, "context", input)

	assert.NoError(t, err)
	assert.Empty(t, spans)
}
