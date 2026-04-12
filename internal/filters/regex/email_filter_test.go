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

func TestEmailAddressFilter_Filter(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		strict   bool
		expected []string
	}{
		{
			name:     "Basic email",
			input:    "My email is test@example.com.",
			strict:   false,
			expected: []string{"test@example.com"},
		},
		{
			name:     "Email with plus",
			input:    "Contact me at test+alias@example.com.",
			strict:   false,
			expected: []string{"test+alias@example.com"},
		},
		{
			name:     "Multiple emails",
			input:    "Emails: one@test.com, two@test.org.",
			strict:   false,
			expected: []string{"one@test.com", "two@test.org"},
		},
		{
			name:     "Strict - valid",
			input:    "My email is test@example.com.",
			strict:   true,
			expected: []string{"test@example.com"},
		},
		{
			name:     "False positive - incomplete",
			input:    "Contact me @example.com",
			strict:   false,
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter := NewEmailAddressFilter(nil, nil, nil, tt.strict)
			pol := &policy.Policy{
				Identifiers: policy.Identifiers{
					EmailAddress: &policy.EmailAddressFilter{
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

func TestEmailAddressFilter_Disabled(t *testing.T) {
	filter := NewEmailAddressFilter(nil, nil, nil, false)
	pol := &policy.Policy{
		Identifiers: policy.Identifiers{
			EmailAddress: nil,
		},
	}

	input := "My email is test@example.com."
	spans, err := filter.Filter(pol, "context", input)

	assert.NoError(t, err)
	assert.Empty(t, spans)
}
