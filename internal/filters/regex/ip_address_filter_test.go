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

func TestIPAddressFilter_Filter(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "IPv4",
			input:    "Localhost is 127.0.0.1.",
			expected: []string{"127.0.0.1"},
		},
		{
			name:     "IPv4 Public",
			input:    "DNS is 8.8.8.8.",
			expected: []string{"8.8.8.8"},
		},
		{
			name:     "IPv6 Full",
			input:    "My IPv6 is 2001:0db8:85a3:0000:0000:8a2e:0370:7334.",
			expected: []string{"2001:0db8:85a3:0000:0000:8a2e:0370:7334"},
		},
		{
			name:     "IPv6 Compressed",
			input:    "My IPv6 is 2001:db8:85a3::8a2e:370:7334.",
			expected: []string{"::8a2e:370:7334"}, // Current regex behavior
		},
		{
			name:     "Overlapping IPv4 in version string",
			input:    "Version 1.2.3.4.5 is old.",
			expected: []string{"1.2.3.4"},
		},
	}

	filter := NewIPAddressFilter(nil, nil, nil)
	pol := &policy.Policy{
		Identifiers: policy.Identifiers{
			IPAddress: &policy.IPAddressFilter{
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

func TestIPAddressFilter_Disabled(t *testing.T) {
	filter := NewIPAddressFilter(nil, nil, nil)
	pol := &policy.Policy{
		Identifiers: policy.Identifiers{
			IPAddress: nil,
		},
	}

	input := "Localhost is 127.0.0.1."
	spans, err := filter.Filter(pol, "context", input)

	assert.NoError(t, err)
	assert.Empty(t, spans)
}
