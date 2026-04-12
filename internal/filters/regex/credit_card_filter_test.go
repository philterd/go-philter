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

func TestCreditCardFilter_Filter(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		onlyValid bool
		expected  []string
	}{
		{
			name:      "Visa - valid",
			input:     "Visa: 4111111111111111.",
			onlyValid: false,
			expected:  []string{"4111111111111111"},
		},
		{
			name:      "Visa - invalid luhn",
			input:     "Visa: 4111111111111112.",
			onlyValid: true,
			expected:  []string{},
		},
		{
			name:      "Visa - invalid luhn but onlyValid false",
			input:     "Visa: 4111111111111112.",
			onlyValid: false,
			expected:  []string{"4111111111111112"},
		},
		{
			name:      "MasterCard - valid",
			input:     "MasterCard: 5105105105105100.",
			onlyValid: true,
			expected:  []string{"5105105105105100"},
		},
		{
			name:      "AMEX - valid",
			input:     "AMEX: 378282246310005.",
			onlyValid: true,
			expected:  []string{"378282246310005"},
		},
		{
			name:      "False positive - short",
			input:     "1234567890",
			onlyValid: false,
			expected:  []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter := NewCreditCardFilter(nil, nil, nil)
			pol := &policy.Policy{
				Identifiers: policy.Identifiers{
					CreditCard: &policy.CreditCardFilter{
						BaseFilter: policy.BaseFilter{
							Enabled: new(true),
						},
						OnlyValidCreditCardNumbers: tt.onlyValid,
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

func TestCreditCardFilter_Disabled(t *testing.T) {
	filter := NewCreditCardFilter(nil, nil, nil)
	pol := &policy.Policy{
		Identifiers: policy.Identifiers{
			CreditCard: nil,
		},
	}

	input := "Visa: 4111111111111111."
	spans, err := filter.Filter(pol, "context", input)

	assert.NoError(t, err)
	assert.Empty(t, spans)
}
