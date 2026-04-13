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
	assert.Equal(t, 1, len(l.docEntries["doc1"]))
	assert.Equal(t, 0, l.docEntries["doc1"][0].Index)

	// First entry's PreviousHash should be all zeros (as per implementation)
	zeroHash := make([]byte, 32)
	assert.True(t, bytes.Equal(zeroHash, l.docEntries["doc1"][0].PreviousHash))

	hash1 := make([]byte, 32)
	copy(hash1, l.docLastHash["doc1"])

	span2 := model.Span{
		Text:           "sensitive2",
		CharacterStart: 20,
		CharacterEnd:   30,
	}

	err = l.Record("doc1", "file1.txt", span2, "replacement2")
	assert.NoError(t, err)
	assert.Equal(t, 2, len(l.docEntries["doc1"]))
	assert.Equal(t, 1, l.docEntries["doc1"][1].Index)

	// Second entry's PreviousHash should be the hash of the first entry
	assert.True(t, bytes.Equal(hash1, l.docEntries["doc1"][1].PreviousHash))
	assert.False(t, bytes.Equal(hash1, l.docLastHash["doc1"]))
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
	assert.NotEqual(t, "sensitive text", l.docEntries["doc1"][0].Text)

	// Retrieval should return decrypted text
	entries, err := l.Get("doc1")
	assert.NoError(t, err)
	assert.Equal(t, 1, len(entries))
	assert.Equal(t, "sensitive text", entries[0].Text)
}

func TestMemoryLedger_Verify(t *testing.T) {
	l := NewMemoryLedger()

	span1 := model.Span{Text: "sensitive1", CharacterStart: 0, CharacterEnd: 10}
	l.Record("doc1", "file1.txt", span1, "replacement1")

	span2 := model.Span{Text: "sensitive2", CharacterStart: 20, CharacterEnd: 30}
	l.Record("doc1", "file1.txt", span2, "replacement2")

	span3 := model.Span{Text: "other", CharacterStart: 0, CharacterEnd: 5}
	l.Record("doc2", "file2.txt", span3, "replacement3")

	// Verify doc1
	ok, err := l.Verify("doc1")
	assert.NoError(t, err)
	assert.True(t, ok)

	// Verify doc2
	ok, err = l.Verify("doc2")
	assert.NoError(t, err)
	assert.True(t, ok)

	// Tamper with an entry
	tamperedEntry := l.docEntries["doc1"][0]
	tamperedEntry.Replacement = "TAMPERED"
	l.docEntries["doc1"][0] = tamperedEntry

	// Verify should now fail
	ok, err = l.Verify("doc1")
	assert.NoError(t, err)
	assert.False(t, ok)

	// doc2 should still be valid as it's a separate chain
	ok, err = l.Verify("doc2")
	assert.NoError(t, err)
	assert.True(t, ok)

}
