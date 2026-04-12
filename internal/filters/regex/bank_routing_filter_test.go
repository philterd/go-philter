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

func TestBankRoutingNumberFilter_Filter(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "Standard routing number",
			input:    "My routing number is 011000015.",
			expected: []string{"011000015"},
		},
		{
			name:     "Another routing number",
			input:    "Use 121100782 for the transfer.",
			expected: []string{"121100782"},
		},
		{
			name:     "Multiple routing numbers",
			input:    "Numbers: 021000021 and 061000052.",
			expected: []string{"021000021", "061000052"},
		},
		{
			name:     "False positive - 8 digits",
			input:    "This is 12345678 only.",
			expected: []string{},
		},
		{
			name:     "False positive - 10 digits",
			input:    "This is 1234567890 only.",
			expected: []string{},
		},
	}

	filter := NewBankRoutingNumberFilter(nil, nil, nil)
	pol := &policy.Policy{
		Identifiers: policy.Identifiers{
			BankRoutingNumber: &policy.BankRoutingNumberFilter{
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

func TestBankRoutingNumberFilter_Disabled(t *testing.T) {
	filter := NewBankRoutingNumberFilter(nil, nil, nil)
	pol := &policy.Policy{
		Identifiers: policy.Identifiers{
			BankRoutingNumber: nil,
		},
	}

	input := "My routing number is 011000015."
	spans, err := filter.Filter(pol, "context", input)

	assert.NoError(t, err)
	assert.Empty(t, spans)
}
