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

package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/philterd/go-phileas/pkg/model"
	"github.com/philterd/go-phileas/pkg/policy"
	"github.com/stretchr/testify/assert"
)

func TestMemoryLedger_Hashing(t *testing.T) {
	l := newMemoryLedger()

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

	l := newMemoryLedger()
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

func TestHandleGetLedger(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.Default()
	r.POST("/api/filter", handleFilter)
	r.GET("/api/ledger", handleGetLedger)

	// Reset ledger
	memLedger := newMemoryLedger()
	ledger = memLedger

	p := &policy.Policy{
		Identifiers: policy.Identifiers{
			SSN: &policy.SSNFilter{
				BaseFilter: policy.BaseFilter{
					Enabled: new(bool),
				},
			},
		},
	}
	*p.Identifiers.SSN.Enabled = true
	policyService.Put("ledger-test-policy", p)

	// Record some redactions
	reqBody1 := FilterRequest{
		Text:       "His SSN is 123-45-6789.",
		DocumentId: "doc123",
		FileName:   "file1.txt",
		PolicyName: "ledger-test-policy",
	}
	body1, _ := json.Marshal(reqBody1)
	req1, _ := http.NewRequest(http.MethodPost, "/api/filter", bytes.NewBuffer(body1))
	resp1 := httptest.NewRecorder()
	r.ServeHTTP(resp1, req1)
	assert.Equal(t, http.StatusOK, resp1.Code)

	// Record another redaction for a different document
	reqBody2 := FilterRequest{
		Text:       "Her SSN is 123-45-6789.",
		DocumentId: "doc456",
		FileName:   "file2.txt",
		PolicyName: "ledger-test-policy",
	}
	body2, _ := json.Marshal(reqBody2)
	req2, _ := http.NewRequest(http.MethodPost, "/api/filter", bytes.NewBuffer(body2))
	resp2 := httptest.NewRecorder()
	r.ServeHTTP(resp2, req2)
	assert.Equal(t, http.StatusOK, resp2.Code)

	// Test GET /api/ledger?documentId=doc123
	req3, _ := http.NewRequest(http.MethodGet, "/api/ledger?documentId=doc123", nil)
	resp3 := httptest.NewRecorder()
	r.ServeHTTP(resp3, req3)

	assert.Equal(t, http.StatusOK, resp3.Code)
	var entries []Entry
	err := json.Unmarshal(resp3.Body.Bytes(), &entries)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(entries))
	assert.Equal(t, "doc123", entries[0].DocumentId)
	assert.Equal(t, "123-45-6789", entries[0].Text)
	assert.NotEmpty(t, entries[0].Replacement)

	// Test GET /api/ledger?documentId=doc456
	req4, _ := http.NewRequest(http.MethodGet, "/api/ledger?documentId=doc456", nil)
	resp4 := httptest.NewRecorder()
	r.ServeHTTP(resp4, req4)

	assert.Equal(t, http.StatusOK, resp4.Code)
	var entries2 []Entry
	err = json.Unmarshal(resp4.Body.Bytes(), &entries2)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(entries2))
	assert.Equal(t, "doc456", entries2[0].DocumentId)

	// Test GET /api/ledger?documentId=nonexistent
	req5, _ := http.NewRequest(http.MethodGet, "/api/ledger?documentId=nonexistent", nil)
	resp5 := httptest.NewRecorder()
	r.ServeHTTP(resp5, req5)

	assert.Equal(t, http.StatusOK, resp5.Code)
	var entries3 []Entry
	json.Unmarshal(resp5.Body.Bytes(), &entries3)
	assert.Equal(t, 0, len(entries3))

	// Test GET /api/ledger without documentId
	req6, _ := http.NewRequest(http.MethodGet, "/api/ledger", nil)
	resp6 := httptest.NewRecorder()
	r.ServeHTTP(resp6, req6)
	assert.Equal(t, http.StatusBadRequest, resp6.Code)
}
