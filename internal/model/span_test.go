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

package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDoesSpanExist(t *testing.T) {
	spans := []Span{
		{CharacterStart: 10, CharacterEnd: 20},
		{CharacterStart: 30, CharacterEnd: 40},
	}

	tests := []struct {
		name           string
		characterStart int
		characterEnd   int
		expected       bool
	}{
		{"Exact match", 10, 20, true},
		{"Within first span", 12, 18, true},
		{"Start match, within first span", 10, 15, true},
		{"End match, within first span", 15, 20, true},
		{"Within second span", 32, 38, true},
		{"No overlap - before first", 0, 5, false},
		{"No overlap - between spans", 21, 29, false},
		{"No overlap - after second", 45, 50, false},
		{"Partial overlap - start before, end within", 5, 15, false}, // Current implementation requires the new span to be WITHIN an existing one
		{"Partial overlap - start within, end after", 15, 25, false}, // Current implementation requires the new span to be WITHIN an existing one
		{"Overlapping multiple spans", 15, 35, false},                // Current implementation requires the new span to be WITHIN an existing one
		{"Larger than existing span", 5, 25, false},                  // Current implementation requires the new span to be WITHIN an existing one
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DoesSpanExist(tt.characterStart, tt.characterEnd, spans)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDropOverlappingSpans(t *testing.T) {
	tests := []struct {
		name     string
		spans    []Span
		expected []Span
	}{
		{
			name:     "Empty slice",
			spans:    []Span{},
			expected: []Span{},
		},
		{
			name: "Single span",
			spans: []Span{
				{CharacterStart: 10, CharacterEnd: 20, Text: "one"},
			},
			expected: []Span{
				{CharacterStart: 10, CharacterEnd: 20, Text: "one"},
			},
		},
		{
			name: "Non-overlapping spans",
			spans: []Span{
				{CharacterStart: 10, CharacterEnd: 20, Text: "one"},
				{CharacterStart: 30, CharacterEnd: 40, Text: "two"},
			},
			expected: []Span{
				{CharacterStart: 10, CharacterEnd: 20, Text: "one"},
				{CharacterStart: 30, CharacterEnd: 40, Text: "two"},
			},
		},
		{
			name: "Overlapping spans - second within first",
			spans: []Span{
				{CharacterStart: 10, CharacterEnd: 20, Text: "one"},
				{CharacterStart: 12, CharacterEnd: 18, Text: "two"},
			},
			expected: []Span{
				{CharacterStart: 10, CharacterEnd: 20, Text: "one"},
			},
		},
		{
			name: "Overlapping spans - first within second",
			spans: []Span{
				{CharacterStart: 12, CharacterEnd: 18, Text: "one"},
				{CharacterStart: 10, CharacterEnd: 20, Text: "two"},
			},
			expected: []Span{
				{CharacterStart: 12, CharacterEnd: 18, Text: "one"},
				{CharacterStart: 10, CharacterEnd: 20, Text: "two"},
			},
		},
		{
			name: "Multiple overlapping spans",
			spans: []Span{
				{CharacterStart: 10, CharacterEnd: 20, Text: "one"},
				{CharacterStart: 15, CharacterEnd: 25, Text: "two"},
				{CharacterStart: 30, CharacterEnd: 40, Text: "three"},
				{CharacterStart: 35, CharacterEnd: 38, Text: "four"},
			},
			expected: []Span{
				{CharacterStart: 10, CharacterEnd: 20, Text: "one"},
				{CharacterStart: 15, CharacterEnd: 25, Text: "two"},
				{CharacterStart: 30, CharacterEnd: 40, Text: "three"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DropOverlappingSpans(tt.spans)
			assert.Equal(t, tt.expected, result)
		})
	}
}
