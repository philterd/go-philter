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

package filters

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/rand"

	"github.com/philterd/go-philter/internal/model"
)

// RandomReplaceForType generates a realistic fake replacement for the given filter type.
// The replacement is deterministic for the same combination of context and text,
// providing referential integrity: the same value in the same context always produces
// the same replacement.
func RandomReplaceForType(filterType model.FilterType, text, context string) string {
	rng := newSeededRand(context, text)
	switch filterType {
	case model.FilterTypeSSN:
		return randomSSN(rng)
	case model.FilterTypeEmailAddress:
		return randomEmail(rng)
	case model.FilterTypePhoneNumber, model.FilterTypePhoneNumberExt:
		return randomPhone(rng)
	case model.FilterTypeCreditCard:
		return randomCreditCard(rng)
	case model.FilterTypeIPAddress:
		return randomIPAddress(rng)
	case model.FilterTypeDate:
		return randomDate(rng)
	case model.FilterTypeZipCode:
		return randomZipCode(rng)
	case model.FilterTypeMACAddress:
		return randomMACAddress(rng)
	case model.FilterTypeVIN:
		return randomVIN(rng)
	case model.FilterTypeBankRoutingNumber:
		return randomBankRoutingNumber(rng)
	case model.FilterTypeBitcoinAddress:
		return randomBitcoinAddress(rng)
	case model.FilterTypeAge:
		return randomAge(rng)
	case model.FilterTypeURL:
		return randomURL(rng)
	case model.FilterTypeIbanCode:
		return randomIBAN(rng)
	case model.FilterTypePassportNumber:
		return randomPassport(rng)
	case model.FilterTypeDriversLicense:
		return randomDriversLicense(rng)
	case model.FilterTypeTrackingNumber:
		return randomTrackingNumber(rng)
	default:
		return "{{{REDACTED-" + string(filterType) + "}}}"
	}
}

// newSeededRand creates a deterministic *rand.Rand seeded from a hash of context and text.
// Using the same context and text always produces the same seed, ensuring referential integrity.
func newSeededRand(context, text string) *rand.Rand {
	h := sha256.Sum256([]byte(context + "\x00" + text))
	seed := int64(binary.BigEndian.Uint64(h[:8]))
	//nolint:gosec // math/rand is intentional here; we need deterministic, reproducible replacements
	return rand.New(rand.NewSource(seed))
}

// randomSSN generates a realistic SSN in XXX-XX-XXXX format using a valid area number.
func randomSSN(rng *rand.Rand) string {
	// Valid area numbers: 001-665, 667-899 (excludes 000, 666, 900-999)
	r := rng.Intn(898) + 1
	area := r
	if r >= 666 {
		area = r + 1
	}
	group := rng.Intn(99) + 1    // 01-99
	serial := rng.Intn(9999) + 1 // 0001-9999
	return fmt.Sprintf("%03d-%02d-%04d", area, group, serial)
}

// randomEmail generates a realistic random email address using example.com / test.org / sample.net.
func randomEmail(rng *rand.Rand) string {
	userLen := rng.Intn(5) + 4 // 4-8 chars
	user := randomLowercaseString(rng, userLen)
	n := rng.Intn(9999) + 1
	domains := []string{"example.com", "test.org", "sample.net"}
	domain := domains[rng.Intn(len(domains))]
	return fmt.Sprintf("%s%d@%s", user, n, domain)
}

// randomPhone generates a realistic US phone number using 555 as the area code.
func randomPhone(rng *rand.Rand) string {
	exchange := rng.Intn(900) + 100
	subscriber := rng.Intn(9000) + 1000
	return fmt.Sprintf("(555) %03d-%04d", exchange, subscriber)
}

// randomCreditCard generates a Luhn-valid 16-digit Visa-like credit card number.
func randomCreditCard(rng *rand.Rand) string {
	digits := make([]int, 16)
	digits[0] = 4 // Visa prefix
	for i := 1; i < 15; i++ {
		digits[i] = rng.Intn(10)
	}
	// Compute Luhn check digit over first 15 digits.
	// We double every second digit starting from the right (positions 2, 4, 6, ... from right).
	// With the check digit at index 15, the digit at index i is at position (16-i) from the right.
	// It should be doubled when (16-i) is even, i.e. when (15-i) is odd.
	sum := 0
	for i := 0; i < 15; i++ {
		d := digits[i]
		if (15-i)%2 == 1 { // odd position from right = even-indexed digit from left
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
	}
	digits[15] = (10 - (sum % 10)) % 10
	return fmt.Sprintf("%d%d%d%d-%d%d%d%d-%d%d%d%d-%d%d%d%d",
		digits[0], digits[1], digits[2], digits[3],
		digits[4], digits[5], digits[6], digits[7],
		digits[8], digits[9], digits[10], digits[11],
		digits[12], digits[13], digits[14], digits[15])
}

// randomIPAddress generates a random IPv4 address in the 192.168.x.x private range.
func randomIPAddress(rng *rand.Rand) string {
	return fmt.Sprintf("192.168.%d.%d", rng.Intn(256), rng.Intn(256))
}

// randomDate generates a random date in MM/DD/YYYY format.
func randomDate(rng *rand.Rand) string {
	year := rng.Intn(50) + 1950 // 1950-1999
	month := rng.Intn(12) + 1   // 01-12
	day := rng.Intn(28) + 1     // 01-28 (safe for all months)
	return fmt.Sprintf("%02d/%02d/%04d", month, day, year)
}

// randomZipCode generates a random 5-digit US ZIP code.
func randomZipCode(rng *rand.Rand) string {
	return fmt.Sprintf("%05d", rng.Intn(100000))
}

// randomMACAddress generates a random locally-administered unicast MAC address.
func randomMACAddress(rng *rand.Rand) string {
	// First octet 02 = locally administered, unicast
	return fmt.Sprintf("02:%02x:%02x:%02x:%02x:%02x",
		rng.Intn(256), rng.Intn(256), rng.Intn(256), rng.Intn(256), rng.Intn(256))
}

// randomVIN generates a random 17-character VIN-like alphanumeric string.
// VIN characters exclude I, O, and Q per ISO 3779.
func randomVIN(rng *rand.Rand) string {
	const vinChars = "ABCDEFGHJKLMNPRSTUVWXYZ0123456789"
	b := make([]byte, 17)
	for i := range b {
		b[i] = vinChars[rng.Intn(len(vinChars))]
	}
	return string(b)
}

// randomBankRoutingNumber generates a random 9-digit US bank routing number.
func randomBankRoutingNumber(rng *rand.Rand) string {
	return fmt.Sprintf("%09d", rng.Intn(1000000000))
}

// randomBitcoinAddress generates a random P2PKH-style Bitcoin address starting with '1'.
func randomBitcoinAddress(rng *rand.Rand) string {
	const base58Chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	length := rng.Intn(8) + 26 // 26-33 chars
	b := make([]byte, length)
	b[0] = '1' // P2PKH prefix
	for i := 1; i < length; i++ {
		b[i] = base58Chars[rng.Intn(len(base58Chars))]
	}
	return string(b)
}

// randomAge generates a random age expression in the form "N years old".
func randomAge(rng *rand.Rand) string {
	age := rng.Intn(80) + 1 // 1-80
	return fmt.Sprintf("%d years old", age)
}

// randomURL generates a random HTTPS URL on example.com.
func randomURL(rng *rand.Rand) string {
	n := rng.Intn(9999) + 1
	paths := []string{"page", "article", "post", "item", "doc"}
	path := paths[rng.Intn(len(paths))]
	return fmt.Sprintf("https://example.com/%s%d", path, n)
}

// randomIBAN generates a random GB IBAN.
func randomIBAN(rng *rand.Rand) string {
	check := rng.Intn(97) + 2 // check digits 02-98
	bankCode := randomUppercaseString(rng, 4)
	sortCode := rng.Intn(1000000)
	account := rng.Intn(100000000)
	return fmt.Sprintf("GB%02d%s%06d%08d", check, bankCode, sortCode, account)
}

// randomPassport generates a random US-style passport number (letter + 8 digits).
func randomPassport(rng *rand.Rand) string {
	letter := byte('A' + rng.Intn(26))
	n := rng.Intn(100000000)
	return fmt.Sprintf("%c%08d", letter, n)
}

// randomDriversLicense generates a random driver's license number (letter + 7 digits).
func randomDriversLicense(rng *rand.Rand) string {
	letter := byte('A' + rng.Intn(26))
	n := rng.Intn(10000000)
	return fmt.Sprintf("%c%07d", letter, n)
}

// randomTrackingNumber generates a random UPS-style tracking number.
func randomTrackingNumber(rng *rand.Rand) string {
	n := rng.Intn(1000000000)
	return fmt.Sprintf("1Z%09d", n)
}

// randomLowercaseString generates a random lowercase alphabetic string of the given length.
func randomLowercaseString(rng *rand.Rand, length int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	b := make([]byte, length)
	for i := range b {
		b[i] = letters[rng.Intn(len(letters))]
	}
	return string(b)
}

// randomUppercaseString generates a random uppercase alphabetic string of the given length.
func randomUppercaseString(rng *rand.Rand, length int) string {
	const letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	b := make([]byte, length)
	for i := range b {
		b[i] = letters[rng.Intn(len(letters))]
	}
	return string(b)
}
