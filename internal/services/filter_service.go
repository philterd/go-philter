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

// Package services provides the filter service for identifying and redacting sensitive information.
package services

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/philterd/go-philter/internal/filters"
	"github.com/philterd/go-philter/internal/filters/dictionary"
	"github.com/philterd/go-philter/internal/filters/pheye"
	"github.com/philterd/go-philter/internal/filters/regex"
	"github.com/philterd/go-philter/internal/model"
	"github.com/philterd/go-philter/internal/policy"
	"sigs.k8s.io/yaml"
)

// FilterService filters sensitive information from text according to a policy.
type FilterService struct {
	filters        []filters.Filter
	contextService ContextService
}

// NewFilterService creates a new FilterService configured according to the given policy.
// The service will apply only the filters enabled in the policy.
// Returns an error if any configured filter cannot be initialized (e.g. a dictionary file cannot be read).
func NewFilterService(pol *policy.Policy) (*FilterService, error) {
	return NewFilterServiceWithContext(pol, NewInMemoryContextService())
}

// NewFilterServiceWithContext creates a new FilterService with a custom ContextService.
// The ContextService is used to store PII tokens and their replacement values to
// establish referential integrity across multiple Filter calls.
// Returns an error if any configured filter cannot be initialized.
func NewFilterServiceWithContext(pol *policy.Policy, contextService ContextService) (*FilterService, error) {
	svc := &FilterService{
		contextService: contextService,
	}
	var err error
	svc.filters, err = buildFilters(pol)
	if err != nil {
		return nil, err
	}
	return svc, nil
}

// Filter applies the policy filters to the input text and returns a FilterResult containing
// the filtered text and the list of identified spans.
func (s *FilterService) Filter(pol *policy.Policy, context string, input string) (*model.FilterResult, error) {
	var allSpans []model.Span

	for _, f := range s.filters {
		spans, err := f.Filter(pol, context, input)
		if err != nil {
			return nil, err
		}
		allSpans = append(allSpans, spans...)
	}

	// Sort spans by position (character start).
	sort.Slice(allSpans, func(i, j int) bool {
		return allSpans[i].CharacterStart < allSpans[j].CharacterStart
	})

	// Build the filtered text by replacing identified spans with their replacements.
	filteredText := applySpans(input, allSpans)

	return &model.FilterResult{
		FilteredText: filteredText,
		Context:      context,
		Spans:        allSpans,
	}, nil
}

// Explain applies the policy filters to the input text and returns the list of identified spans
// without modifying or replacing any text.
func (s *FilterService) Explain(pol *policy.Policy, context string, input string) ([]model.Span, error) {
	var allSpans []model.Span

	for _, f := range s.filters {
		spans, err := f.Filter(pol, context, input)
		if err != nil {
			return nil, err
		}
		allSpans = append(allSpans, spans...)
	}

	// Sort spans by position (character start).
	sort.Slice(allSpans, func(i, j int) bool {
		return allSpans[i].CharacterStart < allSpans[j].CharacterStart
	})

	return allSpans, nil
}

// FilterJSON parses a policy from JSON and applies it to the input text.
// This is a convenience method for one-shot filtering.
func FilterJSON(policyJSON string, context string, input string) (*model.FilterResult, error) {
	var pol policy.Policy
	if err := json.Unmarshal([]byte(policyJSON), &pol); err != nil {
		return nil, err
	}

	svc, err := NewFilterService(&pol)
	if err != nil {
		return nil, err
	}
	return svc.Filter(&pol, context, input)
}

// FilterYAML parses a policy from YAML and applies it to the input text.
// This is a convenience method for one-shot filtering.
func FilterYAML(policyYAML string, context string, input string) (*model.FilterResult, error) {
	var pol policy.Policy
	if err := yaml.Unmarshal([]byte(policyYAML), &pol); err != nil {
		return nil, err
	}

	svc, err := NewFilterService(&pol)
	if err != nil {
		return nil, err
	}
	return svc.Filter(&pol, context, input)
}

// ValidateJSON validates that the given string is a well-formed JSON policy.
// It returns nil if the policy is valid, or an error describing the problem.
func ValidateJSON(policyJSON string) error {
	var pol policy.Policy
	return json.Unmarshal([]byte(policyJSON), &pol)
}

// ValidateYAML validates that the given string is a well-formed YAML policy.
// It returns nil if the policy is valid, or an error describing the problem.
func ValidateYAML(policyYAML string) error {
	var pol policy.Policy
	return yaml.Unmarshal([]byte(policyYAML), &pol)
}

// applySpans replaces the spans in the input text with their replacements.
// Non-overlapping spans are applied in order.
func applySpans(input string, spans []model.Span) string {
	if len(spans) == 0 {
		return input
	}

	var sb strings.Builder
	pos := 0

	for _, span := range spans {
		if span.Ignored || !span.Applied {
			continue
		}
		if span.CharacterStart > pos {
			sb.WriteString(input[pos:span.CharacterStart])
		}
		if span.Replacement != "" {
			sb.WriteString(span.Replacement)
		} else {
			sb.WriteString(span.Text)
		}
		pos = span.CharacterEnd
	}

	if pos < len(input) {
		sb.WriteString(input[pos:])
	}

	return sb.String()
}

// buildFilters creates filters based on the enabled identifiers in the policy.
func buildFilters(pol *policy.Policy) ([]filters.Filter, error) {
	var filterList []filters.Filter

	ids := pol.Identifiers

	if ids.Age != nil && ids.Age.IsEnabled() {
		strategies := ids.Age.AgeFilterStrategies
		filterList = append(filterList, regex.NewAgeFilter(strategies, ids.Age.Ignored, ids.Age.IgnoredPatterns))
	}

	if ids.BankRoutingNumber != nil && ids.BankRoutingNumber.IsEnabled() {
		strategies := ids.BankRoutingNumber.BankRoutingNumberFilterStrategies
		filterList = append(filterList, regex.NewBankRoutingNumberFilter(strategies, ids.BankRoutingNumber.Ignored, ids.BankRoutingNumber.IgnoredPatterns))
	}

	if ids.BitcoinAddress != nil && ids.BitcoinAddress.IsEnabled() {
		strategies := ids.BitcoinAddress.BitcoinAddressFilterStrategies
		filterList = append(filterList, regex.NewBitcoinAddressFilter(strategies, ids.BitcoinAddress.Ignored, ids.BitcoinAddress.IgnoredPatterns))
	}

	if ids.CreditCard != nil && ids.CreditCard.IsEnabled() {
		strategies := ids.CreditCard.CreditCardFilterStrategies
		filterList = append(filterList, regex.NewCreditCardFilter(strategies, ids.CreditCard.Ignored, ids.CreditCard.IgnoredPatterns))
	}

	if ids.Date != nil && ids.Date.IsEnabled() {
		strategies := ids.Date.DateFilterStrategies
		filterList = append(filterList, regex.NewDateFilter(strategies, ids.Date.Ignored, ids.Date.IgnoredPatterns))
	}

	if ids.DriversLicense != nil && ids.DriversLicense.IsEnabled() {
		strategies := ids.DriversLicense.DriversLicenseFilterStrategies
		filterList = append(filterList, regex.NewDriverLicenseFilter(strategies, ids.DriversLicense.Ignored, ids.DriversLicense.IgnoredPatterns))
	}

	if ids.EmailAddress != nil && ids.EmailAddress.IsEnabled() {
		strategies := ids.EmailAddress.EmailAddressFilterStrategies
		filterList = append(filterList, regex.NewEmailAddressFilter(strategies, ids.EmailAddress.Ignored, ids.EmailAddress.IgnoredPatterns, false))
	}

	if ids.IbanCode != nil && ids.IbanCode.IsEnabled() {
		strategies := ids.IbanCode.IbanCodeFilterStrategies
		filterList = append(filterList, regex.NewIBANFilter(strategies, ids.IbanCode.Ignored, ids.IbanCode.IgnoredPatterns))
	}

	if ids.IPAddress != nil && ids.IPAddress.IsEnabled() {
		strategies := ids.IPAddress.IPAddressFilterStrategies
		filterList = append(filterList, regex.NewIPAddressFilter(strategies, ids.IPAddress.Ignored, ids.IPAddress.IgnoredPatterns))
	}

	if ids.MACAddress != nil && ids.MACAddress.IsEnabled() {
		strategies := ids.MACAddress.MACAddressFilterStrategies
		filterList = append(filterList, regex.NewMACAddressFilter(strategies, ids.MACAddress.Ignored, ids.MACAddress.IgnoredPatterns))
	}

	if ids.PassportNumber != nil && ids.PassportNumber.IsEnabled() {
		strategies := ids.PassportNumber.PassportNumberFilterStrategies
		filterList = append(filterList, regex.NewPassportNumberFilter(strategies, ids.PassportNumber.Ignored, ids.PassportNumber.IgnoredPatterns))
	}

	if ids.PhoneNumber != nil && ids.PhoneNumber.IsEnabled() {
		strategies := ids.PhoneNumber.PhoneNumberFilterStrategies
		filterList = append(filterList, regex.NewPhoneNumberFilter(strategies, ids.PhoneNumber.Ignored, ids.PhoneNumber.IgnoredPatterns))
	}

	if ids.SSN != nil && ids.SSN.IsEnabled() {
		strategies := ids.SSN.SSNFilterStrategies
		filterList = append(filterList, regex.NewSSNFilter(strategies, ids.SSN.Ignored, ids.SSN.IgnoredPatterns))
	}

	if ids.TrackingNumber != nil && ids.TrackingNumber.IsEnabled() {
		strategies := ids.TrackingNumber.TrackingNumberFilterStrategies
		filterList = append(filterList, regex.NewTrackingNumberFilter(strategies, ids.TrackingNumber.Ignored, ids.TrackingNumber.IgnoredPatterns))
	}

	if ids.URL != nil && ids.URL.IsEnabled() {
		strategies := ids.URL.URLFilterStrategies
		requirePrefix := ids.URL.RequireHTTPWWWPrefix
		filterList = append(filterList, regex.NewURLFilter(strategies, ids.URL.Ignored, ids.URL.IgnoredPatterns, requirePrefix))
	}

	if ids.VIN != nil && ids.VIN.IsEnabled() {
		strategies := ids.VIN.VINFilterStrategies
		filterList = append(filterList, regex.NewVINFilter(strategies, ids.VIN.Ignored, ids.VIN.IgnoredPatterns))
	}

	if ids.ZipCode != nil && ids.ZipCode.IsEnabled() {
		strategies := ids.ZipCode.ZipCodeFilterStrategies
		requireDelimiter := ids.ZipCode.RequireDelimiter
		filterList = append(filterList, regex.NewZipCodeFilter(strategies, ids.ZipCode.Ignored, ids.ZipCode.IgnoredPatterns, requireDelimiter))
	}

	for _, pheyeCfg := range ids.PhEye {
		if pheyeCfg.IsEnabled() {
			filterList = append(filterList, pheye.NewPhEyeFilter(pheyeCfg))
		}
	}

	for _, dictCfg := range ids.Dictionaries {
		if dictCfg.IsEnabled() {
			f, err := dictionary.NewDictionaryFilter(dictCfg)
			if err != nil {
				return nil, err
			}
			filterList = append(filterList, f)
		}
	}

	return filterList, nil
}
