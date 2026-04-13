package pheye

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/philterd/go-philter/internal/filters"
	"github.com/philterd/go-philter/internal/model"
	"github.com/philterd/go-philter/internal/policy"
)

// PhEyeFilter identifies entities by calling the direct PhEye model.
type PhEyeFilter struct {
	filterConfig policy.PhEyeFilter
	client       Client
	ignored      map[string]struct{}
}

// NewPhEyeFilter creates a new PhEyeFilter from the given filter configuration.
func NewPhEyeFilter(cfg policy.PhEyeFilter) *PhEyeFilter {
	modelPath := cfg.PhEyeConfiguration.ModelPath
	var client Client
	var err error

	// This function is defined in either client_cgo.go or client_mock.go
	if modelPath != "" {
		client, err = newClient(modelPath)
		if err != nil {
			// In a real app we might want to log this or handle it differently
			fmt.Printf("pheye: failed to create client: %v\n", err)
		}
	}

	ignoredSet := make(map[string]struct{}, len(cfg.Ignored))
	for _, term := range cfg.Ignored {
		ignoredSet[strings.ToLower(term)] = struct{}{}
	}

	return &PhEyeFilter{
		filterConfig: cfg,
		client:       client,
		ignored:      ignoredSet,
	}
}

// Close releases the underlying PhEye client.
func (f *PhEyeFilter) Close() error {
	if f.client != nil {
		return f.client.Close()
	}
	return nil
}

// GetFilterType returns the filter type for pheye.
func (f *PhEyeFilter) GetFilterType() model.FilterType {
	return model.FilterTypePhEye
}

// Filter identifies entities using the direct PhEye model.
func (f *PhEyeFilter) Filter(pol *policy.Policy, context string, input string) ([]model.Span, error) {
	if f.client == nil {
		return nil, nil
	}

	if pol == nil || len(pol.Identifiers.PhEye) == 0 {
		return nil, nil
	}

	text := input
	if f.filterConfig.RemovePunctuation {
		text = removePunctuation(text)
	}

	labelsStr := f.filterConfig.PhEyeConfiguration.Labels
	if labelsStr == "" {
		labelsStr = "Person"
	}
	labels := splitLabels(labelsStr)

	entities, err := f.client.Predict(text, labels, 0.5)
	if err != nil {
		return nil, fmt.Errorf("pheye filter: %w", err)
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

func removePunctuation(s string) string {
	var sb strings.Builder
	for _, r := range s {
		if !unicode.IsPunct(r) {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

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
