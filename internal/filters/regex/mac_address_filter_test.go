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

func TestMACAddressFilter_Filter(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "MAC with colons",
			input:    "The MAC address is 00:1A:2B:3C:4D:5E.",
			expected: []string{"00:1A:2B:3C:4D:5E"},
		},
		{
			name:     "MAC with dashes",
			input:    "The MAC address is 00-1A-2B-3C-4D-5E.",
			expected: []string{"00-1A-2B-3C-4D-5E"},
		},
		{
			name:     "MAC Cisco format",
			input:    "The MAC address is 001A.2B3C.4D5E.",
			expected: []string{"001A.2B3C.4D5E"},
		},
		{
			name:     "False positive - short",
			input:    "00:1A:2B",
			expected: []string{},
		},
	}

	filter := NewMACAddressFilter(nil, nil, nil)
	pol := &policy.Policy{
		Identifiers: policy.Identifiers{
			MACAddress: &policy.MACAddressFilter{
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

func TestMACAddressFilter_Disabled(t *testing.T) {
	filter := NewMACAddressFilter(nil, nil, nil)
	pol := &policy.Policy{
		Identifiers: policy.Identifiers{
			MACAddress: nil,
		},
	}

	input := "The MAC address is 00:1A:2B:3C:4D:5E."
	spans, err := filter.Filter(pol, "context", input)

	assert.NoError(t, err)
	assert.Empty(t, spans)
}
