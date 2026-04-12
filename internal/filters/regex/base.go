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

// Package regex provides regex-based filters for identifying sensitive information.
package regex

import (
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/philterd/go-philter/internal/filters"
	"github.com/philterd/go-philter/internal/model"
	"github.com/philterd/go-philter/internal/policy"
)

// FilterPattern describes a single regex pattern used by a filter along with its confidence level.
type FilterPattern struct {
	Pattern    *regexp.Regexp
	Confidence float64
	// GroupNumber is the capture group index used for the match (0 = whole match).
	GroupNumber int
}

// BaseRegexFilter provides the base implementation for regex-based filters.
type BaseRegexFilter struct {
	filterType      model.FilterType
	patterns        []FilterPattern
	strategies      []policy.FilterStrategy
	ignored         map[string]struct{}
	ignoredPatterns []*regexp.Regexp
}

// NewBaseRegexFilter creates a new BaseRegexFilter with the given configuration.
func NewBaseRegexFilter(
	filterType model.FilterType,
	patterns []FilterPattern,
	strategies []policy.FilterStrategy,
	ignored []string,
	ignoredPatterns []policy.IgnoredPattern,
) BaseRegexFilter {
	ignoredSet := make(map[string]struct{}, len(ignored))
	for _, term := range ignored {
		ignoredSet[strings.ToLower(term)] = struct{}{}
	}

	compiledIgnoredPatterns := make([]*regexp.Regexp, 0, len(ignoredPatterns))
	for _, ip := range ignoredPatterns {
		var re *regexp.Regexp
		if ip.CaseSensitive {
			re = regexp.MustCompile(ip.Pattern)
		} else {
			re = regexp.MustCompile("(?i)" + ip.Pattern)
		}
		compiledIgnoredPatterns = append(compiledIgnoredPatterns, re)
	}

	return BaseRegexFilter{
		filterType:      filterType,
		patterns:        patterns,
		strategies:      strategies,
		ignored:         ignoredSet,
		ignoredPatterns: compiledIgnoredPatterns,
	}
}

// GetFilterType returns the filter type.
func (f *BaseRegexFilter) GetFilterType() model.FilterType {
	return f.filterType
}

// isIgnored checks whether a token should be ignored.
func (f *BaseRegexFilter) isIgnored(token string) bool {
	if _, ok := f.ignored[strings.ToLower(token)]; ok {
		return true
	}
	for _, re := range f.ignoredPatterns {
		if re.MatchString(token) {
			return true
		}
	}
	return false
}

// findSpans finds spans matching the filter patterns in the given input text.
func (f *BaseRegexFilter) findSpans(pol *policy.Policy, input string, context string) ([]model.Span, error) {
	var spans []model.Span

	for _, fp := range f.patterns {
		matches := fp.Pattern.FindAllStringSubmatchIndex(input, -1)
		for _, match := range matches {
			// Determine the index into the match slice based on the group number.
			// For group 0 (whole match): match[0], match[1]
			// For group N: match[2*N], match[2*N+1]
			groupIdx := fp.GroupNumber * 2
			if groupIdx+1 >= len(match) {
				groupIdx = 0
			}
			start := match[groupIdx]
			end := match[groupIdx+1]
			if start < 0 || end < 0 {
				continue
			}

			token := input[start:end]

			// Check if a span already exists at this position.
			if model.DoesSpanExist(start, end, spans) {
				continue
			}

			// Check if token is ignored.
			ignored := f.isIgnored(token)

			// Apply the strategy to get the replacement text.
			replacement := ""
			if len(f.strategies) > 0 {
				replacement = applyStrategy(f.strategies[0], f.filterType, token, context)
			} else {
				replacement = "{{{REDACTED-" + string(f.filterType) + "}}}"
			}

			span := model.Span{
				CharacterStart: start,
				CharacterEnd:   end,
				FilterType:     f.filterType,
				Context:        context,
				Confidence:     fp.Confidence,
				Text:           token,
				Replacement:    replacement,
				Ignored:        ignored,
				Applied:        !ignored,
			}
			spans = append(spans, span)
		}
	}

	return spans, nil
}

// applyStrategy applies a filter strategy to produce a replacement string.
// context is used by the RANDOM_REPLACE strategy for referential integrity.
func applyStrategy(s policy.FilterStrategy, filterType model.FilterType, text string, context string) string {
	format := s.RedactionFormat
	if s.Strategy == "" || s.Strategy == policy.StrategyRedact {
		if format == "" {
			format = policy.DefaultRedactionFormat
		}
		result := strings.ReplaceAll(format, "%t", string(filterType))
		result = strings.ReplaceAll(result, "%v", text)
		return result
	}
	if s.Strategy == policy.StrategyRandomReplace {
		return filters.RandomReplaceForType(filterType, text, context)
	}
	if s.Strategy == policy.StrategyStaticReplace {
		return s.StaticReplacement
	}
	if s.Strategy == policy.StrategyMask {
		maskChar := s.MaskCharacter
		if maskChar == "" {
			maskChar = "*"
		}
		return strings.Repeat(maskChar, len(text))
	}
	if s.Strategy == policy.StrategyShiftDate {
		if filterType == model.FilterTypeDate {
			return shiftDate(text, s.ShiftDays, s.ShiftMonths, s.ShiftYears)
		}
		// SHIFT_DATE only applies to dates; fall through to default redact.
	}
	// Default to redact.
	if format == "" {
		format = policy.DefaultRedactionFormat
	}
	return strings.ReplaceAll(format, "%t", string(filterType))
}

// normalizeDateCase converts the first character of each alphabetic run to uppercase
// and the remaining characters to lowercase, leaving non-letter characters unchanged.
// This normalises month names like "JANUARY" or "january" to "January" for time.Parse.
func normalizeDateCase(s string) string {
	var b strings.Builder
	prevAlpha := false
	for _, r := range s {
		if unicode.IsLetter(r) {
			if !prevAlpha {
				b.WriteRune(unicode.ToUpper(r))
			} else {
				b.WriteRune(unicode.ToLower(r))
			}
			prevAlpha = true
		} else {
			b.WriteRune(r)
			prevAlpha = false
		}
	}
	return b.String()
}

// shiftDate parses text as a date, shifts it by the given days/months/years, and
// returns the result formatted in the same style as the input.
// If the input cannot be parsed as a date, the original text is returned unchanged.
//
// Supported input formats (matching those recognised by DateFilter):
//   - ISO 8601:              YYYY-MM-DD  (e.g. "2020-03-15")
//   - US numeric slash:     MM/DD/YYYY   (e.g. "03/15/2020")
//   - US numeric dash:      MM-DD-YYYY   (e.g. "03-15-2020")
//   - US numeric dot:       MM.DD.YYYY   (e.g. "03.15.2020")
//   - Long month, day, year: "January 15, 2020" or "January 15 2020"
//   - Short month, day, year: "Jan 15, 2020" or "Jan 15 2020"
//   - Day, long month, year: "15 January 2020"
//   - Day, short month, year: "15 Jan 2020"
//
// Month names are normalised to title case before parsing; the output always
// uses title-case month names. Numeric dash dates are parsed as MM-DD-YYYY
// (US-style, month first).
func shiftDate(text string, days, months, years int) string {
	if days == 0 && months == 0 && years == 0 {
		return text
	}

	normalized := normalizeDateCase(text)

	// Named-month formats (try both with and without comma, full and abbreviated).
	namedFormats := []string{
		"January 2, 2006",
		"Jan 2, 2006",
		"January 2 2006",
		"Jan 2 2006",
		"2 January 2006",
		"2 Jan 2006",
	}
	for _, f := range namedFormats {
		t, err := time.Parse(f, normalized)
		if err == nil {
			return t.AddDate(years, months, days).Format(f)
		}
	}

	// ISO 8601: YYYY-MM-DD
	if t, err := time.Parse("2006-01-02", text); err == nil {
		return t.AddDate(years, months, days).Format("2006-01-02")
	}

	// Numeric formats: detect separator (/, -, .) and parse as MM<sep>DD<sep>YYYY.
	for _, sep := range []string{"/", ".", "-"} {
		if !strings.Contains(text, sep) {
			continue
		}
		layout := "01" + sep + "02" + sep + "2006"
		if t, err := time.Parse(layout, text); err == nil {
			return t.AddDate(years, months, days).Format(layout)
		}
	}

	// Unparseable – return original text unchanged.
	return text
}
