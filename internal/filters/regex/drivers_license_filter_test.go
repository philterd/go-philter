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

func TestDriverLicenseFilter_Filter(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "Generic format (Letter + 7 digits)",
			input:    "The ID is S1234567.",
			expected: []string{"S1234567"},
		},
		{
			name:     "Numeric (7-9 digits)",
			input:    "The ID is 12345678.",
			expected: []string{"12345678"},
		},
		{
			name:     "Alphanumeric (2 letters + digits)",
			input:    "The ID is AB123456.",
			expected: []string{"AB123456"},
		},
		{
			name:     "False positive - short",
			input:    "123456",
			expected: []string{},
		},
	}

	filter := NewDriverLicenseFilter(nil, nil, nil)
	pol := &policy.Policy{
		Identifiers: policy.Identifiers{
			DriversLicense: &policy.DriversLicenseFilter{
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

func TestDriverLicenseFilter_Disabled(t *testing.T) {
	filter := NewDriverLicenseFilter(nil, nil, nil)
	pol := &policy.Policy{
		Identifiers: policy.Identifiers{
			DriversLicense: nil,
		},
	}

	input := "The ID is S1234567."
	spans, err := filter.Filter(pol, "context", input)

	assert.NoError(t, err)
	assert.Empty(t, spans)
}
