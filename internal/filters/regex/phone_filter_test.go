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

func TestPhoneNumberFilter_Filter(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "US format dash",
			input:    "Call me at 555-555-5555.",
			expected: []string{"555-555-5555"},
		},
		{
			name:     "US format dots",
			input:    "Call me at 555.555.5555.",
			expected: []string{"555.555.5555"},
		},
		{
			name:     "US format parenthesis",
			input:    "Call me at (555) 555-5555.",
			expected: []string{"(555) 555-5555"},
		},
		{
			name:     "US format country code",
			input:    "Call me at +1-555-555-5555.",
			expected: []string{"+1-555-555-5555"},
		},
		{
			name:     "International format",
			input:    "Call me at +44 20 7946 0958.",
			expected: []string{"+44 20 7946 0958"},
		},
		{
			name:     "False positive - short",
			input:    "555-5555",
			expected: []string{},
		},
	}

	filter := NewPhoneNumberFilter(nil, nil, nil)
	pol := &policy.Policy{
		Identifiers: policy.Identifiers{
			PhoneNumber: &policy.PhoneNumberFilter{
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

func TestPhoneNumberFilter_Disabled(t *testing.T) {
	filter := NewPhoneNumberFilter(nil, nil, nil)
	pol := &policy.Policy{
		Identifiers: policy.Identifiers{
			PhoneNumber: nil,
		},
	}

	input := "Call me at 555-555-5555."
	spans, err := filter.Filter(pol, "context", input)

	assert.NoError(t, err)
	assert.Empty(t, spans)
}
