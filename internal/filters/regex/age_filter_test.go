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

func TestAgeFilter_Filter(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "Years old",
			input:    "The patient is 45 years old.",
			expected: []string{"45 years old"},
		},
		{
			name:     "Aged",
			input:    "The patient is aged 30.",
			expected: []string{"aged 30"},
		},
		{
			name:     "Y/o",
			input:    "The patient is 61 y/o.",
			expected: []string{"61 y/o"},
		},
		{
			name:     "Yo",
			input:    "The patient is 25yo.",
			expected: []string{"25yo"},
		},
		{
			name:     "Yrs old",
			input:    "He is 10 yrs old.",
			expected: []string{"10 yrs old"},
		},
		{
			name:     "Multiple ages",
			input:    "The 45 year old man and 30 year old woman.",
			expected: []string{"45 year old", "30 year old"},
		},
		{
			name:     "Age with hyphen",
			input:    "A 50-year-old patient.",
			expected: []string{"50-year-old"},
		},
		{
			name:     "Age with dot",
			input:    "The child is 1.5 years old.",
			expected: []string{"1.5 years old"},
		},
		{
			name:     "False positive - no age terms",
			input:    "There are 100 cars in the lot.",
			expected: []string{},
		},
		{
			name:     "False positive - year without age term",
			input:    "In 2024, everything changed.",
			expected: []string{},
		},
	}

	filter := NewAgeFilter(nil, nil, nil)
	pol := &policy.Policy{
		Identifiers: policy.Identifiers{
			Age: &policy.AgeFilter{
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

func TestAgeFilter_Disabled(t *testing.T) {
	filter := NewAgeFilter(nil, nil, nil)
	pol := &policy.Policy{
		Identifiers: policy.Identifiers{
			Age: nil,
		},
	}

	input := "The patient is 45 years old."
	spans, err := filter.Filter(pol, "context", input)

	assert.NoError(t, err)
	assert.Empty(t, spans)
}

func TestAgeFilter_Ignored(t *testing.T) {
	ignored := []string{"45 years old"}
	filter := NewAgeFilter(nil, ignored, nil)
	pol := &policy.Policy{
		Identifiers: policy.Identifiers{
			Age: &policy.AgeFilter{
				BaseFilter: policy.BaseFilter{
					Enabled: new(true),
				},
			},
		},
	}

	input := "The patient is 45 years old."
	spans, err := filter.Filter(pol, "context", input)

	assert.NoError(t, err)
	assert.Len(t, spans, 1)
	assert.True(t, spans[0].Ignored)
	assert.False(t, spans[0].Applied)
}

func TestAgeFilter_Strategies(t *testing.T) {
	strategies := []policy.FilterStrategy{
		{
			Strategy:        policy.StrategyRedact,
			RedactionFormat: "[AGE]",
		},
	}
	filter := NewAgeFilter(strategies, nil, nil)
	pol := &policy.Policy{
		Identifiers: policy.Identifiers{
			Age: &policy.AgeFilter{
				BaseFilter: policy.BaseFilter{
					Enabled: new(true),
				},
			},
		},
	}

	input := "The patient is 45 years old."
	spans, err := filter.Filter(pol, "context", input)

	assert.NoError(t, err)
	assert.Len(t, spans, 1)
	assert.Equal(t, "[AGE]", spans[0].Replacement)
}
