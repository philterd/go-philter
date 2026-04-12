/*
 * Copyright 2026 Philterd, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package services

import (
	"bytes"
	"os"
	"testing"

	
	"github.com/philterd/go-philter/internal/model"
	
	"github.com/stretchr/testify/assert"
)
func TestMemoryLedger_Hashing(t *testing.T) {
	l := NewMemoryLedger()

	span1 := model.Span{
		Text:           "sensitive1",
		CharacterStart: 0,
		CharacterEnd:   10,
	}

	err := l.Record("doc1", "file1.txt", span1, "replacement1")
	assert.NoError(t, err)
	assert.Equal(t, 1, len(l.entries))

	// First entry's PreviousHash should be all zeros (as per implementation)
	zeroHash := make([]byte, 32)
	assert.True(t, bytes.Equal(zeroHash, l.entries[0].PreviousHash))

	hash1 := make([]byte, 32)
	copy(hash1, l.lastHash)

	span2 := model.Span{
		Text:           "sensitive2",
		CharacterStart: 20,
		CharacterEnd:   30,
	}

	err = l.Record("doc1", "file1.txt", span2, "replacement2")
	assert.NoError(t, err)
	assert.Equal(t, 2, len(l.entries))

	// Second entry's PreviousHash should be the hash of the first entry
	assert.True(t, bytes.Equal(hash1, l.entries[1].PreviousHash))
	assert.False(t, bytes.Equal(hash1, l.lastHash))
}

func TestMemoryLedger_Encryption(t *testing.T) {
	// Set encryption key
	key := "1234567890123456" // 16 bytes
	os.Setenv("LEDGER_ENCRYPTION_KEY", key)
	defer os.Unsetenv("LEDGER_ENCRYPTION_KEY")

	l := NewMemoryLedger()
	assert.NotNil(t, l.encryptionKey)

	span := model.Span{
		Text:           "sensitive text",
		CharacterStart: 0,
		CharacterEnd:   14,
	}

	err := l.Record("doc1", "file1.txt", span, "replacement")
	assert.NoError(t, err)

	// Internally, the text should be encrypted
	assert.NotEqual(t, "sensitive text", l.entries[0].Text)

	// Retrieval should return decrypted text
	entries, err := l.Get("doc1")
	assert.NoError(t, err)
	assert.Equal(t, 1, len(entries))
	assert.Equal(t, "sensitive text", entries[0].Text)
}

