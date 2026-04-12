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

func TestBitcoinAddressFilter_Filter(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "Legacy P2PKH",
			input:    "My address is 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa.",
			expected: []string{"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"},
		},
		{
			name:     "Legacy P2SH",
			input:    "Send it to 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy.",
			expected: []string{"3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"},
		},
		{
			name:     "Bech32 P2WPKH",
			input:    "My Bech32 address: bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq.",
			expected: []string{"bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"},
		},
		{
			name:     "False positive - short",
			input:    "Address 1234567890",
			expected: []string{},
		},
	}

	filter := NewBitcoinAddressFilter(nil, nil, nil)
	pol := &policy.Policy{
		Identifiers: policy.Identifiers{
			BitcoinAddress: &policy.BitcoinAddressFilter{
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

func TestBitcoinAddressFilter_Disabled(t *testing.T) {
	filter := NewBitcoinAddressFilter(nil, nil, nil)
	pol := &policy.Policy{
		Identifiers: policy.Identifiers{
			BitcoinAddress: nil,
		},
	}

	input := "My address is 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa."
	spans, err := filter.Filter(pol, "context", input)

	assert.NoError(t, err)
	assert.Empty(t, spans)
}
