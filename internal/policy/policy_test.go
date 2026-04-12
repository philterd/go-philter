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

package policy

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBaseFilter_IsEnabled(t *testing.T) {
	tests := []struct {
		name     string
		enabled  *bool
		expected bool
	}{
		{
			name:     "nil enabled defaults to true",
			enabled:  nil,
			expected: true,
		},
		{
			name:     "explicit true",
			enabled:  new(bool),
			expected: true,
		},
		{
			name:     "explicit false",
			enabled:  new(bool),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.enabled != nil && tt.name == "explicit true" {
				*tt.enabled = true
			} else if tt.enabled != nil && tt.name == "explicit false" {
				*tt.enabled = false
			}
			bf := BaseFilter{Enabled: tt.enabled}
			assert.Equal(t, tt.expected, bf.IsEnabled())
		})
	}
}

func TestPolicy_UnmarshalJSON(t *testing.T) {
	jsonData := `{
		"identifiers": {
			"ssn": {
				"enabled": true,
				"ssnFilterStrategies": [
					{
						"strategy": "REDACT",
						"redactionFormat": "{{{REDACTED-%t}}}"
					}
				]
			},
			"age": {
				"enabled": false
			}
		},
		"ignored": [
			{
				"terms": ["ignore-me"]
			}
		],
		"crypto": {
			"key": "secret",
			"iv": "vector"
		}
	}`

	var p Policy
	err := json.Unmarshal([]byte(jsonData), &p)
	assert.NoError(t, err)

	assert.NotNil(t, p.Identifiers.SSN)
	assert.True(t, p.Identifiers.SSN.IsEnabled())
	assert.Len(t, p.Identifiers.SSN.SSNFilterStrategies, 1)
	assert.Equal(t, "REDACT", p.Identifiers.SSN.SSNFilterStrategies[0].Strategy)

	assert.NotNil(t, p.Identifiers.Age)
	assert.False(t, p.Identifiers.Age.IsEnabled())

	assert.Len(t, p.Ignored, 1)
	assert.Contains(t, p.Ignored[0].Terms, "ignore-me")

	assert.NotNil(t, p.Crypto)
	assert.Equal(t, "secret", p.Crypto.Key)
	assert.Equal(t, "vector", p.Crypto.IV)
}

func TestFilterStrategy_UnmarshalJSON(t *testing.T) {
	jsonData := `{
		"strategy": "SHIFT_DATE",
		"shiftDays": 5,
		"shiftMonths": 2,
		"shiftYears": 1
	}`

	var fs FilterStrategy
	err := json.Unmarshal([]byte(jsonData), &fs)
	assert.NoError(t, err)

	assert.Equal(t, "SHIFT_DATE", fs.Strategy)
	assert.Equal(t, 5, fs.ShiftDays)
	assert.Equal(t, 2, fs.ShiftMonths)
	assert.Equal(t, 1, fs.ShiftYears)
}

func TestIgnoredPattern_UnmarshalJSON(t *testing.T) {
	jsonData := `{
		"name": "test-pattern",
		"pattern": "[0-9]+",
		"caseSensitive": true
	}`

	var ip IgnoredPattern
	err := json.Unmarshal([]byte(jsonData), &ip)
	assert.NoError(t, err)

	assert.Equal(t, "test-pattern", ip.Name)
	assert.Equal(t, "[0-9]+", ip.Pattern)
	assert.True(t, ip.CaseSensitive)
}
