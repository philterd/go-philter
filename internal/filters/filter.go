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

// Package filters provides the Filter interface and filter implementations for
// identifying sensitive information in text.
package filters

import (
	"github.com/philterd/go-philter/internal/model"
	"github.com/philterd/go-philter/internal/policy"
)

// Filter is the interface implemented by all filters.
// Each Filter identifies a specific type of sensitive information in text.
type Filter interface {
	// Filter analyzes the input text and returns a list of identified spans.
	// policy is the policy to apply.
	// context is the context name for the filtering operation.
	// input is the text to filter.
	Filter(pol *policy.Policy, context string, input string) ([]model.Span, error)

	// GetFilterType returns the type of sensitive information this filter identifies.
	GetFilterType() model.FilterType
}

// FilterConfiguration holds configuration options for a filter.
type FilterConfiguration struct {
	// Strategies defines how identified spans should be handled.
	Strategies []policy.FilterStrategy
	// Ignored is a set of terms to ignore.
	Ignored []string
	// IgnoredPatterns is a list of patterns to ignore.
	IgnoredPatterns []policy.IgnoredPattern
}

// ApplyStrategy applies the given strategy to a span's text.
// context is used by the RANDOM_REPLACE strategy for referential integrity.
// It returns the replacement string based on the strategy.
func ApplyStrategy(strategy policy.FilterStrategy, filterType model.FilterType, text string, context string) string {
	if strategy.Strategy == "" || strategy.Strategy == policy.StrategyRedact {
		format := strategy.RedactionFormat
		if format == "" {
			format = policy.DefaultRedactionFormat
		}
		// Replace %t with the filter type string
		result := replaceAll(format, "%t", string(filterType))
		// Replace %v with the original value
		result = replaceAll(result, "%v", text)
		return result
	}
	if strategy.Strategy == policy.StrategyRandomReplace {
		return RandomReplaceForType(filterType, text, context)
	}
	if strategy.Strategy == policy.StrategyStaticReplace {
		return strategy.StaticReplacement
	}
	if strategy.Strategy == policy.StrategyMask {
		maskChar := strategy.MaskCharacter
		if maskChar == "" {
			maskChar = "*"
		}
		masked := make([]byte, len(text))
		for i := range masked {
			masked[i] = maskChar[0]
		}
		return string(masked)
	}
	// SHIFT_DATE is handled by the regex base layer which has access to the filter type;
	// at this public API level, defer to the default redact for unsupported strategies.
	// Default to redact for unsupported strategies
	format := policy.DefaultRedactionFormat
	return replaceAll(format, "%t", string(filterType))
}

// replaceAll replaces all occurrences of old with new in s.
func replaceAll(s, old, new string) string {
	result := []byte{}
	for i := 0; i < len(s); {
		if i+len(old) <= len(s) && s[i:i+len(old)] == old {
			result = append(result, new...)
			i += len(old)
		} else {
			result = append(result, s[i])
			i++
		}
	}
	return string(result)
}
