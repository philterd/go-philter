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

// FilterType represents the type of sensitive information identified by a filter.
type FilterType string

const (
	FilterTypeAge               FilterType = "age"
	FilterTypeBankRoutingNumber FilterType = "bank-routing-number"
	FilterTypeBitcoinAddress    FilterType = "bitcoin-address"
	FilterTypeCreditCard        FilterType = "credit-card"
	FilterTypeCurrency          FilterType = "currency"
	FilterTypeDate              FilterType = "date"
	FilterTypeDriversLicense    FilterType = "drivers-license-number"
	FilterTypeEmailAddress      FilterType = "email-address"
	FilterTypeIbanCode          FilterType = "iban-code"
	FilterTypeIdentifier        FilterType = "id"
	FilterTypeIPAddress         FilterType = "ip-address"
	FilterTypeMACAddress        FilterType = "mac-address"
	FilterTypePassportNumber    FilterType = "passport-number"
	FilterTypePhoneNumber       FilterType = "phone-number"
	FilterTypePhoneNumberExt    FilterType = "phone-number-extension"
	FilterTypeSSN               FilterType = "ssn"
	FilterTypeStreetAddress     FilterType = "street-address"
	FilterTypeTrackingNumber    FilterType = "tracking-number"
	FilterTypeURL               FilterType = "url"
	FilterTypeVIN               FilterType = "vin"
	FilterTypeZipCode           FilterType = "zip-code"
	FilterTypeCity              FilterType = "city"
	FilterTypeCounty            FilterType = "county"
	FilterTypeState             FilterType = "state"
	FilterTypeStateAbbreviation FilterType = "state-abbreviation"
	FilterTypeFirstName         FilterType = "first-name"
	FilterTypeSurname           FilterType = "surname"
	FilterTypeHospital          FilterType = "hospital"
	FilterTypeCustomDictionary  FilterType = "custom-dictionary"
	FilterTypePerson            FilterType = "person"
	FilterTypeMedicalCondition  FilterType = "medical-condition"
	FilterTypePhEye             FilterType = "pheye"
)
