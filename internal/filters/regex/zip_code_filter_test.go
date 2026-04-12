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

func TestZipCodeFilter_Filter(t *testing.T) {
	tests := []struct {
		name             string
		input            string
		requireDelimiter bool
		expected         []string
	}{
		{
			name:             "5-digit ZIP",
			input:            "The ZIP code is 12345.",
			requireDelimiter: true,
			expected:         []string{"12345"},
		},
		{
			name:             "ZIP+4 with dash",
			input:            "The ZIP code is 12345-6789.",
			requireDelimiter: true,
			expected:         []string{"12345-6789"},
		},
		{
			name:             "ZIP+4 without dash (required)",
			input:            "The ZIP code is 12345 6789.",
			requireDelimiter: true,
			expected:         []string{"12345"},
		},
		{
			name:             "ZIP+4 without dash (not required)",
			input:            "The ZIP code is 123456789.",
			requireDelimiter: false,
			expected:         []string{"123456789"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter := NewZipCodeFilter(nil, nil, nil, tt.requireDelimiter)
			pol := &policy.Policy{
				Identifiers: policy.Identifiers{
					ZipCode: &policy.ZipCodeFilter{
						BaseFilter: policy.BaseFilter{
							Enabled: new(true),
						},
					},
				},
			}

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

func TestZipCodeFilter_Disabled(t *testing.T) {
	filter := NewZipCodeFilter(nil, nil, nil, true)
	pol := &policy.Policy{
		Identifiers: policy.Identifiers{
			ZipCode: nil,
		},
	}

	input := "The ZIP code is 12345."
	spans, err := filter.Filter(pol, "context", input)

	assert.NoError(t, err)
	assert.Empty(t, spans)
}
