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

// Package policy provides types for defining Phileas policies.
// A policy specifies which types of sensitive information to identify and how to handle them.
package policy

// Strategy constants define how identified sensitive information should be handled.
const (
	// StrategyRedact replaces the sensitive information with a redaction placeholder.
	StrategyRedact = "REDACT"
	// StrategyRandomReplace replaces the sensitive information with a random but realistic value.
	StrategyRandomReplace = "RANDOM_REPLACE"
	// StrategyStaticReplace replaces the sensitive information with a fixed static value.
	StrategyStaticReplace = "STATIC_REPLACE"
	// StrategyCryptoReplace encrypts the sensitive information.
	StrategyCryptoReplace = "CRYPTO_REPLACE"
	// StrategyHashSHA256Replace replaces the sensitive information with its SHA-256 hash.
	StrategyHashSHA256Replace = "HASH_SHA256_REPLACE"
	// StrategyLast4 keeps only the last 4 characters of the sensitive information.
	StrategyLast4 = "LAST_4"
	// StrategyMask masks the sensitive information with a mask character.
	StrategyMask = "MASK"
	// StrategyShiftDate shifts an identified date by a configurable number of days, months, and/or years.
	// Only applies to date filter types; other filter types fall back to REDACT.
	StrategyShiftDate = "SHIFT_DATE"

	// DefaultRedactionFormat is the default format for redacted values.
	DefaultRedactionFormat = "{{{REDACTED-%t}}}"

	// FuzzyLow allows fuzzy matching with a Levenshtein distance of 1.
	FuzzyLow = "low"
	// FuzzyMedium allows fuzzy matching with a Levenshtein distance of 2.
	FuzzyMedium = "medium"
	// FuzzyHigh allows fuzzy matching with a Levenshtein distance of 3.
	FuzzyHigh = "high"
)

// FilterStrategy defines how to handle identified sensitive information.
type FilterStrategy struct {
	// Strategy is the action to take when sensitive information is found.
	// Valid values: REDACT, RANDOM_REPLACE, STATIC_REPLACE, CRYPTO_REPLACE, HASH_SHA256_REPLACE, LAST_4, MASK, SHIFT_DATE.
	Strategy string `json:"strategy"`
	// RedactionFormat is the format string for redaction placeholders. Use %t for filter type.
	// Defaults to "{{{REDACTED-%t}}}".
	RedactionFormat string `json:"redactionFormat,omitempty"`
	// StaticReplacement is the fixed text to use when strategy is STATIC_REPLACE.
	StaticReplacement string `json:"staticReplacement,omitempty"`
	// MaskCharacter is the character used to mask sensitive information when strategy is MASK.
	MaskCharacter string `json:"maskCharacter,omitempty"`
	// ShiftDays is the number of days to add (or subtract if negative) when strategy is SHIFT_DATE.
	ShiftDays int `json:"shiftDays,omitempty"`
	// ShiftMonths is the number of months to add (or subtract if negative) when strategy is SHIFT_DATE.
	ShiftMonths int `json:"shiftMonths,omitempty"`
	// ShiftYears is the number of years to add (or subtract if negative) when strategy is SHIFT_DATE.
	ShiftYears int `json:"shiftYears,omitempty"`
}

// Ignored represents a term that should be ignored by all filters.
type Ignored struct {
	// Terms is the list of terms to ignore.
	Terms []string `json:"terms,omitempty"`
	// Files is a list of file paths containing terms to ignore.
	Files []string `json:"files,omitempty"`
}

// IgnoredPattern represents a regex pattern for text that should be ignored.
type IgnoredPattern struct {
	// Name is a descriptive name for the pattern.
	Name string `json:"name,omitempty"`
	// Pattern is the regex pattern to match text that should be ignored.
	Pattern string `json:"pattern"`
	// CaseSensitive indicates whether the pattern match is case-sensitive.
	CaseSensitive bool `json:"caseSensitive,omitempty"`
}

// Crypto holds encryption configuration.
type Crypto struct {
	// Key is the encryption key.
	Key string `json:"key,omitempty"`
	// IV is the initialization vector for AES encryption.
	IV string `json:"iv,omitempty"`
}

// Policy defines what sensitive information to identify and how to handle it.
// Policies are serializable to/from JSON.
type Policy struct {
	// Identifiers defines which types of sensitive information to look for.
	Identifiers Identifiers `json:"identifiers"`
	// Ignored is the list of terms to ignore globally across all filters.
	Ignored []Ignored `json:"ignored,omitempty"`
	// IgnoredPatterns is the list of patterns to ignore globally across all filters.
	IgnoredPatterns []IgnoredPattern `json:"ignoredPatterns,omitempty"`
	// Crypto holds encryption configuration.
	Crypto *Crypto `json:"crypto,omitempty"`
}

// BaseFilter contains configuration common to all filter types.
type BaseFilter struct {
	// Enabled indicates whether this filter is active. Defaults to true if the filter is present.
	Enabled *bool `json:"enabled,omitempty"`
	// Ignored is a list of terms specific to this filter to ignore.
	Ignored []string `json:"ignored,omitempty"`
	// IgnoredFiles is a list of file paths containing terms to ignore for this filter.
	IgnoredFiles []string `json:"ignoredFiles,omitempty"`
	// IgnoredPatterns is a list of patterns for this filter to ignore.
	IgnoredPatterns []IgnoredPattern `json:"ignoredPatterns,omitempty"`
}

// IsEnabled returns true if the filter is enabled (defaults to true if not explicitly set).
func (b BaseFilter) IsEnabled() bool {
	return b.Enabled == nil || *b.Enabled
}
