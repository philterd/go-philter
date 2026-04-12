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

package dictionary

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/philterd/go-philter/internal/model"
	"github.com/philterd/go-philter/internal/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDictionaryFilter_Filter_Exact(t *testing.T) {
	cfg := policy.DictionaryFilter{
		Terms: []string{"apple", "banana", "Cherry"},
	}

	f, err := NewDictionaryFilter(cfg)
	require.NoError(t, err)

	pol := &policy.Policy{
		Identifiers: policy.Identifiers{
			Dictionaries: []policy.DictionaryFilter{cfg},
		},
	}

	tests := []struct {
		name     string
		input    string
		expected []model.Span
	}{
		{
			name:  "match lowercase",
			input: "I like apple and banana.",
			expected: []model.Span{
				{Text: "apple", CharacterStart: 7, CharacterEnd: 12},
				{Text: "banana", CharacterStart: 17, CharacterEnd: 23},
			},
		},
		{
			name:  "match mixed case (case-insensitive by default)",
			input: "Apple and Banana are fruits.",
			expected: []model.Span{
				{Text: "Apple", CharacterStart: 0, CharacterEnd: 5},
				{Text: "Banana", CharacterStart: 10, CharacterEnd: 16},
			},
		},
		{
			name:     "no match",
			input:    "The orange is juicy.",
			expected: nil,
		},
		{
			name:     "word boundaries",
			input:    "pineapple and bananarama",
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spans, err := f.Filter(pol, "ctx", tt.input)
			require.NoError(t, err)
			assert.Equal(t, len(tt.expected), len(spans))
			for i, exp := range tt.expected {
				assert.Equal(t, exp.Text, spans[i].Text)
				assert.Equal(t, exp.CharacterStart, spans[i].CharacterStart)
				assert.Equal(t, exp.CharacterEnd, spans[i].CharacterEnd)
			}
		})
	}
}

func TestDictionaryFilter_Filter_CaseSensitive(t *testing.T) {
	cfg := policy.DictionaryFilter{
		Terms:         []string{"apple", "Banana"},
		CaseSensitive: true,
	}

	f, err := NewDictionaryFilter(cfg)
	require.NoError(t, err)

	pol := &policy.Policy{
		Identifiers: policy.Identifiers{
			Dictionaries: []policy.DictionaryFilter{cfg},
		},
	}

	tests := []struct {
		name     string
		input    string
		expected []model.Span
	}{
		{
			name:  "exact case match",
			input: "apple and Banana",
			expected: []model.Span{
				{Text: "apple", CharacterStart: 0, CharacterEnd: 5},
				{Text: "Banana", CharacterStart: 10, CharacterEnd: 16},
			},
		},
		{
			name:     "mismatched case",
			input:    "Apple and banana",
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spans, err := f.Filter(pol, "ctx", tt.input)
			require.NoError(t, err)
			assert.Equal(t, len(tt.expected), len(spans))
		})
	}
}

func TestDictionaryFilter_Filter_Fuzzy(t *testing.T) {
	cfg := policy.DictionaryFilter{
		Terms: []string{"apple", "banana"},
		Fuzzy: "medium", // maxDist 2, confidence 0.6
	}

	f, err := NewDictionaryFilter(cfg)
	require.NoError(t, err)

	pol := &policy.Policy{
		Identifiers: policy.Identifiers{
			Dictionaries: []policy.DictionaryFilter{cfg},
		},
	}

	tests := []struct {
		name     string
		input    string
		expected []model.Span
	}{
		{
			name:  "exact match (skipped by fuzzy, caught by exact)",
			input: "apple",
			expected: []model.Span{
				{Text: "apple", Confidence: 1.0},
			},
		},
		{
			name:  "fuzzy match distance 1",
			input: "aple",
			expected: []model.Span{
				{Text: "aple", Confidence: 0.6},
			},
		},
		{
			name:  "fuzzy match distance 2",
			input: "applee",
			expected: []model.Span{
				{Text: "applee", Confidence: 0.6},
			},
		},
		{
			name:  "no fuzzy match distance 3",
			input: "appl", // distance 1 from apple
			expected: []model.Span{
				{Text: "appl", Confidence: 0.6},
			},
		},
		{
			name:     "no fuzzy match far",
			input:    "orange",
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spans, err := f.Filter(pol, "ctx", tt.input)
			require.NoError(t, err)
			assert.Equal(t, len(tt.expected), len(spans))
			for i, exp := range tt.expected {
				assert.Equal(t, exp.Text, spans[i].Text)
				assert.Equal(t, exp.Confidence, spans[i].Confidence)
			}
		})
	}
}

func TestDictionaryFilter_Filter_Ignored(t *testing.T) {
	cfg := policy.DictionaryFilter{
		BaseFilter: policy.BaseFilter{
			Ignored: []string{"apple"},
			IgnoredPatterns: []policy.IgnoredPattern{
				{Pattern: "^ban.*$", CaseSensitive: false},
			},
		},
		Terms: []string{"apple", "banana"},
	}

	f, err := NewDictionaryFilter(cfg)
	require.NoError(t, err)

	pol := &policy.Policy{
		Identifiers: policy.Identifiers{
			Dictionaries: []policy.DictionaryFilter{cfg},
		},
	}

	input := "apple banana cherry"
	spans, err := f.Filter(pol, "ctx", input)
	require.NoError(t, err)

	// Both apple and banana should be found but marked as ignored
	assert.Equal(t, 2, len(spans))
	for _, span := range spans {
		assert.True(t, span.Ignored)
		assert.False(t, span.Applied)
	}
}

func TestDictionaryFilter_Filter_Strategies(t *testing.T) {
	tests := []struct {
		name        string
		strategy    policy.FilterStrategy
		expectedRep string
	}{
		{
			name: "default redact",
			strategy: policy.FilterStrategy{
				Strategy: policy.StrategyRedact,
			},
			expectedRep: "{{{REDACTED-custom-dictionary}}}",
		},
		{
			name: "custom format redact",
			strategy: policy.FilterStrategy{
				Strategy:        policy.StrategyRedact,
				RedactionFormat: "[%t: %v]",
			},
			expectedRep: "[custom-dictionary: apple]",
		},
		{
			name: "static replace",
			strategy: policy.FilterStrategy{
				Strategy:          policy.StrategyStaticReplace,
				StaticReplacement: "FRUIT",
			},
			expectedRep: "FRUIT",
		},
		{
			name: "mask",
			strategy: policy.FilterStrategy{
				Strategy:      policy.StrategyMask,
				MaskCharacter: "*",
			},
			expectedRep: "*****",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := policy.DictionaryFilter{
				Terms:                      []string{"apple"},
				DictionaryFilterStrategies: []policy.FilterStrategy{tt.strategy},
			}
			f, err := NewDictionaryFilter(cfg)
			require.NoError(t, err)

			pol := &policy.Policy{
				Identifiers: policy.Identifiers{
					Dictionaries: []policy.DictionaryFilter{cfg},
				},
			}

			spans, err := f.Filter(pol, "ctx", "apple")
			require.NoError(t, err)
			require.Len(t, spans, 1)
			assert.Equal(t, tt.expectedRep, spans[0].Replacement)
		})
	}
}

func TestDictionaryFilter_Filter_Files(t *testing.T) {
	// Create a temporary file with words
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "dict.txt")
	words := "apple\nbanana\ncherry\n"
	err := os.WriteFile(tmpFile, []byte(words), 0644)
	require.NoError(t, err)

	cfg := policy.DictionaryFilter{
		Files: []string{tmpFile},
	}

	f, err := NewDictionaryFilter(cfg)
	require.NoError(t, err)

	pol := &policy.Policy{
		Identifiers: policy.Identifiers{
			Dictionaries: []policy.DictionaryFilter{cfg},
		},
	}

	spans, err := f.Filter(pol, "ctx", "I have an apple.")
	require.NoError(t, err)
	require.Len(t, spans, 1)
	assert.Equal(t, "apple", spans[0].Text)
}

func TestDictionaryFilter_New_Error(t *testing.T) {
	cfg := policy.DictionaryFilter{
		Files: []string{"non-existent-file.txt"},
	}

	_, err := NewDictionaryFilter(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot open file")
}

func TestDictionaryFilter_GetFilterType(t *testing.T) {
	f := &DictionaryFilter{}
	assert.Equal(t, model.FilterTypeCustomDictionary, f.GetFilterType())
}

func TestLevenshtein(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"", "", 0},
		{"a", "", 1},
		{"", "a", 1},
		{"abc", "abc", 0},
		{"abc", "abd", 1},
		{"kitten", "sitting", 3},
		{"rosettacode", "raisethysword", 8},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.want, levenshtein(tt.a, tt.b), "levenshtein(%q, %q)", tt.a, tt.b)
	}
}
