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

// Package dictionary provides a filter that identifies words from a custom dictionary.
package dictionary

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
	"unicode"

	"github.com/philterd/go-philter/internal/model"
	"github.com/philterd/go-philter/internal/policy"
)

// DictionaryFilter identifies words from a custom dictionary in text.
type DictionaryFilter struct {
	filterConfig    policy.DictionaryFilter
	strategies      []policy.FilterStrategy
	words           []string
	wordPatterns    []*regexp.Regexp
	ignored         map[string]struct{}
	ignoredPatterns []*regexp.Regexp
}

// NewDictionaryFilter creates a new DictionaryFilter from the given filter configuration.
// Terms from cfg.Terms and from files listed in cfg.Files are compiled into word-boundary
// regex patterns. Returns an error if any file cannot be read.
func NewDictionaryFilter(cfg policy.DictionaryFilter) (*DictionaryFilter, error) {
	words, err := collectWords(cfg)
	if err != nil {
		return nil, err
	}

	wordPatterns := make([]*regexp.Regexp, 0, len(words))
	for _, w := range words {
		if w == "" {
			continue
		}
		pattern := `(?i)\b` + regexp.QuoteMeta(w) + `\b`
		if cfg.CaseSensitive {
			pattern = `\b` + regexp.QuoteMeta(w) + `\b`
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("dictionary filter: invalid word pattern %q: %w", w, err)
		}
		wordPatterns = append(wordPatterns, re)
	}

	ignoredSet := make(map[string]struct{}, len(cfg.Ignored))
	for _, term := range cfg.Ignored {
		ignoredSet[strings.ToLower(term)] = struct{}{}
	}

	compiledIgnoredPatterns := make([]*regexp.Regexp, 0, len(cfg.IgnoredPatterns))
	for _, ip := range cfg.IgnoredPatterns {
		var re *regexp.Regexp
		if ip.CaseSensitive {
			re = regexp.MustCompile(ip.Pattern)
		} else {
			re = regexp.MustCompile("(?i)" + ip.Pattern)
		}
		compiledIgnoredPatterns = append(compiledIgnoredPatterns, re)
	}

	return &DictionaryFilter{
		filterConfig:    cfg,
		strategies:      cfg.DictionaryFilterStrategies,
		words:           words,
		wordPatterns:    wordPatterns,
		ignored:         ignoredSet,
		ignoredPatterns: compiledIgnoredPatterns,
	}, nil
}

// GetFilterType returns the filter type for dictionary filters.
func (f *DictionaryFilter) GetFilterType() model.FilterType {
	return model.FilterTypeCustomDictionary
}

// Filter finds spans in the input text that match the configured dictionary words.
func (f *DictionaryFilter) Filter(pol *policy.Policy, context string, input string) ([]model.Span, error) {
	if pol == nil || len(pol.Identifiers.Dictionaries) == 0 {
		return nil, nil
	}

	var spans []model.Span

	for _, re := range f.wordPatterns {
		matches := re.FindAllStringIndex(input, -1)
		for _, match := range matches {
			start, end := match[0], match[1]
			token := input[start:end]

			if model.DoesSpanExist(start, end, spans) {
				continue
			}

			ignored := f.isIgnored(token)

			replacement := ""
			if len(f.strategies) > 0 {
				replacement = applyStrategy(f.strategies[0], model.FilterTypeCustomDictionary, token, context)
			} else {
				replacement = "{{{REDACTED-" + string(model.FilterTypeCustomDictionary) + "}}}"
			}

			spans = append(spans, model.Span{
				CharacterStart: start,
				CharacterEnd:   end,
				FilterType:     model.FilterTypeCustomDictionary,
				Context:        context,
				Confidence:     1.0,
				Text:           token,
				Replacement:    replacement,
				Ignored:        ignored,
				Applied:        !ignored,
			})
		}
	}

	// Perform fuzzy matching if configured.
	if f.filterConfig.Fuzzy != "" {
		maxDist := fuzzyMaxDistance(f.filterConfig.Fuzzy)
		confidence := fuzzyConfidence(f.filterConfig.Fuzzy)
		fuzzySpans := f.fuzzyFilter(input, context, maxDist, confidence, spans)
		spans = append(spans, fuzzySpans...)
	}

	return model.DropOverlappingSpans(spans), nil
}

// fuzzyFilter finds tokens in input that are within maxDist Levenshtein distance of any dictionary word.
// exactSpans contains spans already found by exact matching, so we skip those token positions.
func (f *DictionaryFilter) fuzzyFilter(input, context string, maxDist int, confidence float64, exactSpans []model.Span) []model.Span {
	var spans []model.Span

	// Tokenize input into words with their byte positions.
	tokens := tokenizeWithPositions(input)

	for _, tok := range tokens {
		// Skip tokens already covered by an exact match.
		if model.DoesSpanExist(tok.start, tok.end, exactSpans) {
			continue
		}

		candidate := tok.text
		compareCandidate := candidate
		if !f.filterConfig.CaseSensitive {
			compareCandidate = strings.ToLower(candidate)
		}

		bestDist := maxDist + 1
		for _, dictWord := range f.words {
			compareDictWord := dictWord
			if !f.filterConfig.CaseSensitive {
				compareDictWord = strings.ToLower(dictWord)
			}

			// Skip exact matches (already handled by regex matching).
			if compareCandidate == compareDictWord {
				bestDist = maxDist + 1
				break
			}

			dist := levenshtein(compareCandidate, compareDictWord)
			if dist < bestDist {
				bestDist = dist
			}
		}

		if bestDist <= maxDist {
			ignored := f.isIgnored(candidate)

			replacement := ""
			if len(f.strategies) > 0 {
				replacement = applyStrategy(f.strategies[0], model.FilterTypeCustomDictionary, candidate, context)
			} else {
				replacement = "{{{REDACTED-" + string(model.FilterTypeCustomDictionary) + "}}}"
			}

			spans = append(spans, model.Span{
				CharacterStart: tok.start,
				CharacterEnd:   tok.end,
				FilterType:     model.FilterTypeCustomDictionary,
				Context:        context,
				Confidence:     confidence,
				Text:           candidate,
				Replacement:    replacement,
				Ignored:        ignored,
				Applied:        !ignored,
			})
		}
	}

	return spans
}

// token holds a word and its byte-range positions in the source string.
type token struct {
	text  string
	start int
	end   int
}

// tokenizeWithPositions splits input into word tokens and records their byte positions.
func tokenizeWithPositions(input string) []token {
	var tokens []token
	start := -1
	for i, r := range input {
		isWord := unicode.IsLetter(r) || unicode.IsDigit(r) || r == '\''
		if isWord && start == -1 {
			start = i
		} else if !isWord && start != -1 {
			tokens = append(tokens, token{text: input[start:i], start: start, end: i})
			start = -1
		}
	}
	if start != -1 {
		tokens = append(tokens, token{text: input[start:], start: start, end: len(input)})
	}
	return tokens
}

// fuzzyMaxDistance maps a fuzzy level string to a maximum Levenshtein distance.
func fuzzyMaxDistance(level string) int {
	switch level {
	case policy.FuzzyLow:
		return 1
	case policy.FuzzyMedium:
		return 2
	case policy.FuzzyHigh:
		return 3
	default:
		return 1
	}
}

// fuzzyConfidence maps a fuzzy level string to a confidence score.
func fuzzyConfidence(level string) float64 {
	switch level {
	case policy.FuzzyLow:
		return 0.8
	case policy.FuzzyMedium:
		return 0.6
	case policy.FuzzyHigh:
		return 0.4
	default:
		return 0.8
	}
}

// levenshtein computes the Levenshtein distance between two strings.
func levenshtein(a, b string) int {
	ra := []rune(a)
	rb := []rune(b)
	la, lb := len(ra), len(rb)

	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}

	// Use two rows for space efficiency.
	prev := make([]int, lb+1)
	curr := make([]int, lb+1)

	for j := 0; j <= lb; j++ {
		prev[j] = j
	}

	for i := 1; i <= la; i++ {
		curr[0] = i
		for j := 1; j <= lb; j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			del := prev[j] + 1
			ins := curr[j-1] + 1
			sub := prev[j-1] + cost
			curr[j] = min3(del, ins, sub)
		}
		prev, curr = curr, prev
	}

	return prev[lb]
}

// min3 returns the minimum of three integers.
func min3(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}

// isIgnored checks whether a token should be ignored.
func (f *DictionaryFilter) isIgnored(token string) bool {
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

// collectWords gathers all words from the cfg.Terms list and from any files listed in cfg.Files.
func collectWords(cfg policy.DictionaryFilter) ([]string, error) {
	seen := make(map[string]struct{})
	var words []string

	add := func(w string) {
		w = strings.TrimSpace(w)
		if w == "" {
			return
		}
		key := strings.ToLower(w)
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			words = append(words, w)
		}
	}

	for _, w := range cfg.Terms {
		add(w)
	}

	for _, path := range cfg.Files {
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("dictionary filter: cannot open file %q: %w", path, err)
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			add(scanner.Text())
		}
		f.Close()
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("dictionary filter: error reading file %q: %w", path, err)
		}
	}

	return words, nil
}

// applyStrategy applies a filter strategy to produce a replacement string.
func applyStrategy(s policy.FilterStrategy, filterType model.FilterType, text string, context string) string {
	if s.Strategy == "" || s.Strategy == policy.StrategyRedact {
		format := s.RedactionFormat
		if format == "" {
			format = policy.DefaultRedactionFormat
		}
		result := strings.ReplaceAll(format, "%t", string(filterType))
		result = strings.ReplaceAll(result, "%v", text)
		return result
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
	// Default to redact.
	format := policy.DefaultRedactionFormat
	return strings.ReplaceAll(format, "%t", string(filterType))
}
