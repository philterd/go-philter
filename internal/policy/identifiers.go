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

package policy

// AgeFilterStrategies wraps a list of age filter strategies for JSON deserialization.
type AgeFilterStrategies struct {
	FilterStrategy
}

// AgeFilter configures detection and handling of ages.
type AgeFilter struct {
	BaseFilter
	// AgeFilterStrategies defines how to handle identified ages.
	AgeFilterStrategies []FilterStrategy `json:"ageFilterStrategies,omitempty"`
}

// BankRoutingNumberFilter configures detection and handling of bank routing numbers.
type BankRoutingNumberFilter struct {
	BaseFilter
	// BankRoutingNumberFilterStrategies defines how to handle identified bank routing numbers.
	BankRoutingNumberFilterStrategies []FilterStrategy `json:"bankRoutingNumberFilterStrategies,omitempty"`
}

// BitcoinAddressFilter configures detection and handling of Bitcoin addresses.
type BitcoinAddressFilter struct {
	BaseFilter
	// BitcoinAddressFilterStrategies defines how to handle identified Bitcoin addresses.
	BitcoinAddressFilterStrategies []FilterStrategy `json:"bitcoinAddressFilterStrategies,omitempty"`
}

// CreditCardFilter configures detection and handling of credit card numbers.
type CreditCardFilter struct {
	BaseFilter
	// CreditCardFilterStrategies defines how to handle identified credit card numbers.
	CreditCardFilterStrategies []FilterStrategy `json:"creditCardFilterStrategies,omitempty"`
	// OnlyValidCreditCardNumbers when true only matches numbers that pass Luhn check.
	OnlyValidCreditCardNumbers bool `json:"onlyValidCreditCardNumbers,omitempty"`
}

// CurrencyFilter configures detection and handling of currency amounts.
type CurrencyFilter struct {
	BaseFilter
	// CurrencyFilterStrategies defines how to handle identified currency amounts.
	CurrencyFilterStrategies []FilterStrategy `json:"currencyFilterStrategies,omitempty"`
}

// DateFilter configures detection and handling of dates.
type DateFilter struct {
	BaseFilter
	// DateFilterStrategies defines how to handle identified dates.
	DateFilterStrategies []FilterStrategy `json:"dateFilterStrategies,omitempty"`
	// OnlyValidDates when true only matches dates that are calendar-valid.
	OnlyValidDates bool `json:"onlyValidDates,omitempty"`
}

// DriversLicenseFilter configures detection and handling of driver's license numbers.
type DriversLicenseFilter struct {
	BaseFilter
	// DriversLicenseFilterStrategies defines how to handle identified driver's license numbers.
	DriversLicenseFilterStrategies []FilterStrategy `json:"driversLicenseFilterStrategies,omitempty"`
}

// EmailAddressFilter configures detection and handling of email addresses.
type EmailAddressFilter struct {
	BaseFilter
	// EmailAddressFilterStrategies defines how to handle identified email addresses.
	EmailAddressFilterStrategies []FilterStrategy `json:"emailAddressFilterStrategies,omitempty"`
	// OnlyValidTLDs when true only matches email addresses with valid top-level domains.
	OnlyValidTLDs bool `json:"onlyValidTLDs,omitempty"`
}

// IbanCodeFilter configures detection and handling of IBAN codes.
type IbanCodeFilter struct {
	BaseFilter
	// IbanCodeFilterStrategies defines how to handle identified IBAN codes.
	IbanCodeFilterStrategies []FilterStrategy `json:"ibanCodeFilterStrategies,omitempty"`
}

// IPAddressFilter configures detection and handling of IP addresses.
type IPAddressFilter struct {
	BaseFilter
	// IPAddressFilterStrategies defines how to handle identified IP addresses.
	IPAddressFilterStrategies []FilterStrategy `json:"ipAddressFilterStrategies,omitempty"`
}

// MACAddressFilter configures detection and handling of MAC addresses.
type MACAddressFilter struct {
	BaseFilter
	// MACAddressFilterStrategies defines how to handle identified MAC addresses.
	MACAddressFilterStrategies []FilterStrategy `json:"macAddressFilterStrategies,omitempty"`
}

// PassportNumberFilter configures detection and handling of passport numbers.
type PassportNumberFilter struct {
	BaseFilter
	// PassportNumberFilterStrategies defines how to handle identified passport numbers.
	PassportNumberFilterStrategies []FilterStrategy `json:"passportNumberFilterStrategies,omitempty"`
}

// PhoneNumberFilter configures detection and handling of phone numbers.
type PhoneNumberFilter struct {
	BaseFilter
	// PhoneNumberFilterStrategies defines how to handle identified phone numbers.
	PhoneNumberFilterStrategies []FilterStrategy `json:"phoneNumberFilterStrategies,omitempty"`
}

// PhoneNumberExtensionFilter configures detection and handling of phone number extensions.
type PhoneNumberExtensionFilter struct {
	BaseFilter
	// PhoneNumberExtensionFilterStrategies defines how to handle identified phone number extensions.
	PhoneNumberExtensionFilterStrategies []FilterStrategy `json:"phoneNumberExtensionFilterStrategies,omitempty"`
}

// SSNFilter configures detection and handling of Social Security Numbers.
type SSNFilter struct {
	BaseFilter
	// SSNFilterStrategies defines how to handle identified SSNs.
	SSNFilterStrategies []FilterStrategy `json:"ssnFilterStrategies,omitempty"`
}

// StreetAddressFilter configures detection and handling of street addresses.
type StreetAddressFilter struct {
	BaseFilter
	// StreetAddressFilterStrategies defines how to handle identified street addresses.
	StreetAddressFilterStrategies []FilterStrategy `json:"streetAddressFilterStrategies,omitempty"`
}

// TrackingNumberFilter configures detection and handling of package tracking numbers.
type TrackingNumberFilter struct {
	BaseFilter
	// TrackingNumberFilterStrategies defines how to handle identified tracking numbers.
	TrackingNumberFilterStrategies []FilterStrategy `json:"trackingNumberFilterStrategies,omitempty"`
}

// URLFilter configures detection and handling of URLs.
type URLFilter struct {
	BaseFilter
	// URLFilterStrategies defines how to handle identified URLs.
	URLFilterStrategies []FilterStrategy `json:"urlFilterStrategies,omitempty"`
	// RequireHTTPWWWPrefix when true only matches URLs with http/https or www prefix.
	RequireHTTPWWWPrefix bool `json:"requireHttpWwwPrefix,omitempty"`
}

// VINFilter configures detection and handling of Vehicle Identification Numbers.
type VINFilter struct {
	BaseFilter
	// VINFilterStrategies defines how to handle identified VINs.
	VINFilterStrategies []FilterStrategy `json:"vinFilterStrategies,omitempty"`
}

// ZipCodeFilter configures detection and handling of ZIP codes.
type ZipCodeFilter struct {
	BaseFilter
	// ZipCodeFilterStrategies defines how to handle identified ZIP codes.
	ZipCodeFilterStrategies []FilterStrategy `json:"zipCodeFilterStrategies,omitempty"`
	// RequireDelimiter when true requires the dash delimiter in ZIP+4 codes.
	RequireDelimiter bool `json:"requireDelimiter,omitempty"`
}

// PhEyeConfiguration holds connection settings for the ph-eye NER service.
type PhEyeConfiguration struct {
	// Endpoint is the ph-eye service URL. Defaults to "http://localhost:18080".
	Endpoint string `json:"endpoint,omitempty"`
	// Timeout is the connection timeout in seconds. Defaults to 600.
	Timeout int `json:"timeout,omitempty"`
	// Labels is a comma-separated list of entity labels to detect. Defaults to "Person".
	Labels string `json:"labels,omitempty"`
}

// DictionaryFilter configures detection and handling of words from a custom dictionary.
type DictionaryFilter struct {
	BaseFilter
	// DictionaryFilterStrategies defines how to handle identified dictionary words.
	DictionaryFilterStrategies []FilterStrategy `json:"dictionaryFilterStrategies,omitempty"`
	// Terms is a list of terms to redact.
	Terms []string `json:"terms,omitempty"`
	// Files is a list of file paths containing words (one per line) to redact.
	Files []string `json:"files,omitempty"`
	// CaseSensitive indicates whether word matching is case-sensitive. Defaults to false.
	CaseSensitive bool `json:"caseSensitive,omitempty"`
	// Fuzzy enables fuzzy (approximate) matching using Levenshtein distance.
	// Valid values: "low" (distance 1), "medium" (distance 2), "high" (distance 3).
	// Fuzzy matches receive a lower confidence score than exact matches.
	Fuzzy string `json:"fuzzy,omitempty"`
}

// PhEyeFilter configures detection and handling of person names using the ph-eye NER service.
type PhEyeFilter struct {
	BaseFilter
	// PhEyeConfiguration holds the connection configuration for the ph-eye service.
	PhEyeConfiguration PhEyeConfiguration `json:"phEyeConfiguration,omitempty"`
	// PhEyeFilterStrategies defines how to handle identified person names.
	PhEyeFilterStrategies []FilterStrategy `json:"phEyeFilterStrategies,omitempty"`
	// RemovePunctuation when true removes punctuation before sending text to ph-eye.
	RemovePunctuation bool `json:"removePunctuation,omitempty"`
	// BearerToken is an optional bearer token for authenticating with the ph-eye service.
	BearerToken string `json:"bearerToken,omitempty"`
	// WindowSize overrides the context window size for this filter.
	WindowSize int `json:"windowSize,omitempty"`
	// Priority is used for tie-breaking when two spans are otherwise identical.
	Priority int `json:"priority,omitempty"`
}

// Identifiers defines which types of sensitive information to identify within a policy.
type Identifiers struct {
	// Age configures age detection.
	Age *AgeFilter `json:"age,omitempty"`
	// BankRoutingNumber configures bank routing number detection.
	BankRoutingNumber *BankRoutingNumberFilter `json:"bankRoutingNumber,omitempty"`
	// BitcoinAddress configures Bitcoin address detection.
	BitcoinAddress *BitcoinAddressFilter `json:"bitcoinAddress,omitempty"`
	// CreditCard configures credit card number detection.
	CreditCard *CreditCardFilter `json:"creditCard,omitempty"`
	// Currency configures currency amount detection.
	Currency *CurrencyFilter `json:"currency,omitempty"`
	// Date configures date detection.
	Date *DateFilter `json:"date,omitempty"`
	// DriversLicense configures driver's license number detection.
	DriversLicense *DriversLicenseFilter `json:"driversLicense,omitempty"`
	// EmailAddress configures email address detection.
	EmailAddress *EmailAddressFilter `json:"emailAddress,omitempty"`
	// IbanCode configures IBAN code detection.
	IbanCode *IbanCodeFilter `json:"ibanCode,omitempty"`
	// IPAddress configures IP address detection.
	IPAddress *IPAddressFilter `json:"ipAddress,omitempty"`
	// MACAddress configures MAC address detection.
	MACAddress *MACAddressFilter `json:"macAddress,omitempty"`
	// PassportNumber configures passport number detection.
	PassportNumber *PassportNumberFilter `json:"passportNumber,omitempty"`
	// PhoneNumber configures phone number detection.
	PhoneNumber *PhoneNumberFilter `json:"phoneNumber,omitempty"`
	// PhoneNumberExtension configures phone number extension detection.
	PhoneNumberExtension *PhoneNumberExtensionFilter `json:"phoneNumberExtension,omitempty"`
	// SSN configures Social Security Number detection.
	SSN *SSNFilter `json:"ssn,omitempty"`
	// StreetAddress configures street address detection.
	StreetAddress *StreetAddressFilter `json:"streetAddress,omitempty"`
	// TrackingNumber configures tracking number detection.
	TrackingNumber *TrackingNumberFilter `json:"trackingNumber,omitempty"`
	// URL configures URL detection.
	URL *URLFilter `json:"url,omitempty"`
	// VIN configures Vehicle Identification Number detection.
	VIN *VINFilter `json:"vin,omitempty"`
	// ZipCode configures ZIP code detection.
	ZipCode *ZipCodeFilter `json:"zipCode,omitempty"`
	// PhEye configures person name detection using the ph-eye NER service.
	// Multiple ph-eye filters may be configured, each pointing to a different service instance.
	PhEye []PhEyeFilter `json:"pheye,omitempty"`
	// Dictionaries configures custom dictionary-based detection.
	// Multiple dictionary filters may be configured, each with its own word list.
	Dictionaries []DictionaryFilter `json:"dictionaries,omitempty"`
}
