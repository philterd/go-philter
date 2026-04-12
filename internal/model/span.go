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

// Span represents a location in text identified as sensitive information.
type Span struct {
	// CharacterStart is the character-based index of the start of the span.
	CharacterStart int `json:"characterStart"`
	// CharacterEnd is the character-based index of the end of the span.
	CharacterEnd int `json:"characterEnd"`
	// FilterType is the type of the identified sensitive information.
	FilterType FilterType `json:"filterType"`
	// Context is the name of the context in which the span was identified.
	Context string `json:"context"`
	// Confidence is the confidence that this is sensitive information (0.0 to 1.0).
	Confidence float64 `json:"confidence"`
	// Text is the text identified as sensitive.
	Text string `json:"text"`
	// Replacement is the replacement text for the sensitive information.
	Replacement string `json:"replacement"`
	// Salt is the salt used for hashing, if any.
	Salt string `json:"salt,omitempty"`
	// Ignored indicates whether this span was ignored per policy.
	Ignored bool `json:"ignored"`
	// Applied indicates whether the replacement was applied.
	Applied bool `json:"applied"`
	// Classification is a custom label for the sensitive information type.
	Classification string `json:"classification,omitempty"`
}

// DoesSpanExist checks if a span already exists at the given character positions.
func DoesSpanExist(characterStart, characterEnd int, spans []Span) bool {
	for _, span := range spans {
		if characterStart >= span.CharacterStart && characterEnd <= span.CharacterEnd {
			return true
		}
	}
	return false
}

// DropOverlappingSpans removes overlapping spans, keeping the first match (highest priority).
func DropOverlappingSpans(spans []Span) []Span {
	result := make([]Span, 0, len(spans))
	for _, span := range spans {
		if !DoesSpanExist(span.CharacterStart, span.CharacterEnd, result) {
			result = append(result, span)
		}
	}
	return result
}
