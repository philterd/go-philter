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

func TestVINFilter_Filter(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "Valid VIN",
			input:    "VIN: 1HGCP2684BR03975A.",
			expected: []string{"1HGCP2684BR03975A"},
		},
		{
			name:     "False positive - short",
			input:    "1HGCP2684BR03975",
			expected: []string{},
		},
		{
			name:     "False positive - long",
			input:    "1HGCP2684BR03975AA",
			expected: []string{},
		},
		{
			name:     "Invalid characters I, O, Q",
			input:    "1HGCP2684BR03975I, 1HGCP2684BR03975O, 1HGCP2684BR03975Q",
			expected: []string{},
		},
	}

	filter := NewVINFilter(nil, nil, nil)
	pol := &policy.Policy{
		Identifiers: policy.Identifiers{
			VIN: &policy.VINFilter{
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

func TestVINFilter_Disabled(t *testing.T) {
	filter := NewVINFilter(nil, nil, nil)
	pol := &policy.Policy{
		Identifiers: policy.Identifiers{
			VIN: nil,
		},
	}

	input := "VIN: 1HGCP2684BR03975A."
	spans, err := filter.Filter(pol, "context", input)

	assert.NoError(t, err)
	assert.Empty(t, spans)
}
