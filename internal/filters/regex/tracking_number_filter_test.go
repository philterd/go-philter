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

func TestTrackingNumberFilter_Filter(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "UPS Tracking Number",
			input:    "UPS Tracking: 1Z12345E0291980793.",
			expected: []string{"1Z12345E0291980793"},
		},
		{
			name:     "FedEx Tracking Number",
			input:    "FedEx Tracking: 123456789012.",
			expected: []string{"123456789012"},
		},
		{
			name:     "USPS Tracking Number",
			input:    "USPS Tracking: 9400100000000000000000.",
			expected: []string{"9400100000000000000000"},
		},
		{
			name:     "USPS Priority Express",
			input:    "USPS Express: EA12345678US.",
			expected: []string{"EA12345678US"},
		},
	}

	filter := NewTrackingNumberFilter(nil, nil, nil)
	pol := &policy.Policy{
		Identifiers: policy.Identifiers{
			TrackingNumber: &policy.TrackingNumberFilter{
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

func TestTrackingNumberFilter_Disabled(t *testing.T) {
	filter := NewTrackingNumberFilter(nil, nil, nil)
	pol := &policy.Policy{
		Identifiers: policy.Identifiers{
			TrackingNumber: nil,
		},
	}

	input := "UPS Tracking: 1Z12345E0291980793."
	spans, err := filter.Filter(pol, "context", input)

	assert.NoError(t, err)
	assert.Empty(t, spans)
}
