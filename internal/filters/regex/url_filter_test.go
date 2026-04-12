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

func TestURLFilter_Filter(t *testing.T) {
	tests := []struct {
		name                 string
		input                string
		requireHTTPWWWPrefix bool
		expected             []string
	}{
		{
			name:                 "URL with https",
			input:                "Visit https://www.philterd.ai for more info.",
			requireHTTPWWWPrefix: true,
			expected:             []string{"https://www.philterd.ai"},
		},
		{
			name:                 "URL with www",
			input:                "Visit www.philterd.ai for more info.",
			requireHTTPWWWPrefix: true,
			expected:             []string{"www.philterd.ai"},
		},
		{
			name:                 "URL without prefix (not allowed)",
			input:                "Visit philterd.ai for more info.",
			requireHTTPWWWPrefix: true,
			expected:             []string{},
		},
		{
			name:                 "URL without prefix (allowed)",
			input:                "Visit philterd.ai for more info.",
			requireHTTPWWWPrefix: false,
			expected:             []string{"philterd.ai"},
		},
		{
			name:                 "URL with port and path",
			input:                "Go to http://localhost:8080/api/test.",
			requireHTTPWWWPrefix: false,
			expected:             nil, // No match due to lack of dots
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter := NewURLFilter(nil, nil, nil, tt.requireHTTPWWWPrefix)
			pol := &policy.Policy{
				Identifiers: policy.Identifiers{
					URL: &policy.URLFilter{
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

func TestURLFilter_Disabled(t *testing.T) {
	filter := NewURLFilter(nil, nil, nil, false)
	pol := &policy.Policy{
		Identifiers: policy.Identifiers{
			URL: nil,
		},
	}

	input := "Visit https://www.philterd.ai for more info."
	spans, err := filter.Filter(pol, "context", input)

	assert.NoError(t, err)
	assert.Empty(t, spans)
}
