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

// Package pheye provides a filter that identifies person names using the ph-eye NER service.
package pheye

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/philterd/go-philter/internal/filters"
	"github.com/philterd/go-philter/internal/model"
	"github.com/philterd/go-philter/internal/policy"
)

const (
	defaultEndpoint = "http://localhost:18080"
	defaultTimeout  = 600
	defaultLabels   = "Person"
)

// phEyeRequest is the JSON body sent to the ph-eye /find endpoint.
type phEyeRequest struct {
	Text      string   `json:"text"`
	Threshold float64  `json:"threshold"`
	Labels    []string `json:"labels"`
}

// phEyeEntity is a single entity returned by the ph-eye service.
type phEyeEntity struct {
	Start int     `json:"start"`
	End   int     `json:"end"`
	Label string  `json:"label"`
	Score float64 `json:"score"`
	Text  string  `json:"text"`
}

// PhEyeFilter identifies person names by calling the ph-eye NER service.
type PhEyeFilter struct {
	filterConfig policy.PhEyeFilter
	httpClient   *http.Client
	ignored      map[string]struct{}
}

// NewPhEyeFilter creates a new PhEyeFilter from the given filter configuration.
func NewPhEyeFilter(cfg policy.PhEyeFilter) *PhEyeFilter {
	timeout := cfg.PhEyeConfiguration.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}

	ignoredSet := make(map[string]struct{}, len(cfg.Ignored))
	for _, term := range cfg.Ignored {
		ignoredSet[strings.ToLower(term)] = struct{}{}
	}

	return &PhEyeFilter{
		filterConfig: cfg,
		httpClient: &http.Client{
			Timeout: time.Duration(timeout) * time.Second,
		},
		ignored: ignoredSet,
	}
}

// GetFilterType returns the filter type for ph-eye.
func (f *PhEyeFilter) GetFilterType() model.FilterType {
	return model.FilterTypePhEye
}

// Filter sends the input text to the ph-eye service and returns identified person-name spans.
func (f *PhEyeFilter) Filter(pol *policy.Policy, context string, input string) ([]model.Span, error) {
	if pol == nil || len(pol.Identifiers.PhEye) == 0 {
		return nil, nil
	}

	text := input
	if f.filterConfig.RemovePunctuation {
		text = removePunctuation(text)
	}

	endpoint := f.filterConfig.PhEyeConfiguration.Endpoint
	if endpoint == "" {
		endpoint = defaultEndpoint
	}

	labelsStr := f.filterConfig.PhEyeConfiguration.Labels
	if labelsStr == "" {
		labelsStr = defaultLabels
	}
	labels := splitLabels(labelsStr)

	entities, err := f.callPhEye(endpoint, text, labels)
	if err != nil {
		return nil, fmt.Errorf("ph-eye filter: %w", err)
	}

	strategies := f.filterConfig.PhEyeFilterStrategies

	var spans []model.Span
	for _, entity := range entities {
		token := entity.Text

		ignored := false
		if _, ok := f.ignored[strings.ToLower(token)]; ok {
			ignored = true
		}

		replacement := ""
		if len(strategies) > 0 {
			replacement = applyStrategy(strategies[0], model.FilterTypePhEye, token, context)
		} else {
			replacement = "{{{REDACTED-" + string(model.FilterTypePhEye) + "}}}"
		}

		spans = append(spans, model.Span{
			CharacterStart: entity.Start,
			CharacterEnd:   entity.End,
			FilterType:     model.FilterTypePhEye,
			Context:        context,
			Confidence:     entity.Score,
			Text:           token,
			Replacement:    replacement,
			Ignored:        ignored,
			Applied:        !ignored,
		})
	}

	return model.DropOverlappingSpans(spans), nil
}

// callPhEye posts the request to the ph-eye /find endpoint and returns the entities.
func (f *PhEyeFilter) callPhEye(endpoint string, text string, labels []string) ([]phEyeEntity, error) {
	reqBody := phEyeRequest{
		Text:      text,
		Threshold: 0.5,
		Labels:    labels,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	url := strings.TrimRight(endpoint, "/") + "/find"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	bearerToken := f.filterConfig.BearerToken
	if bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+bearerToken)
	}

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ph-eye service returned status %d", resp.StatusCode)
	}

	var entities []phEyeEntity
	if err := json.NewDecoder(resp.Body).Decode(&entities); err != nil {
		return nil, err
	}

	return entities, nil
}

// splitLabels splits a comma-separated labels string into a slice, trimming whitespace.
func splitLabels(s string) []string {
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

// removePunctuation removes punctuation characters from the text.
func removePunctuation(s string) string {
	var sb strings.Builder
	for _, r := range s {
		if !unicode.IsPunct(r) {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// applyStrategy applies a filter strategy to produce a replacement string.
func applyStrategy(strategy policy.FilterStrategy, filterType model.FilterType, text string, context string) string {
	if strategy.Strategy == "" || strategy.Strategy == policy.StrategyRedact {
		format := strategy.RedactionFormat
		if format == "" {
			format = policy.DefaultRedactionFormat
		}
		result := strings.ReplaceAll(format, "%t", string(filterType))
		result = strings.ReplaceAll(result, "%v", text)
		return result
	}
	if strategy.Strategy == policy.StrategyRandomReplace {
		return filters.RandomReplaceForType(filterType, text, context)
	}
	if strategy.Strategy == policy.StrategyStaticReplace {
		return strategy.StaticReplacement
	}
	if strategy.Strategy == policy.StrategyMask {
		maskChar := strategy.MaskCharacter
		if maskChar == "" {
			maskChar = "*"
		}
		return strings.Repeat(maskChar, len(text))
	}
	format := policy.DefaultRedactionFormat
	return strings.ReplaceAll(format, "%t", string(filterType))
}
