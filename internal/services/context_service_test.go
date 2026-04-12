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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInMemoryContextService(t *testing.T) {
	s := NewInMemoryContextService()

	// Test Put and Get
	s.Put("ctx1", "token1", "replacement1")
	val, found := s.Get("ctx1", "token1")
	assert.True(t, found)
	assert.Equal(t, "replacement1", val)

	// Test Get non-existent
	val, found = s.Get("ctx1", "non-existent")
	assert.False(t, found)
	assert.Empty(t, val)

	val, found = s.Get("non-existent", "token1")
	assert.False(t, found)
	assert.Empty(t, val)

	// Test Count
	s.Put("ctx1", "token2", "replacement2")
	count, err := s.Count("ctx1")
	assert.NoError(t, err)
	assert.Equal(t, 2, count)

	count, err = s.Count("non-existent")
	assert.NoError(t, err)
	assert.Equal(t, 0, count)

	// Test List
	s.Put("ctx2", "token3", "replacement3")
	list, err := s.List()
	assert.NoError(t, err)
	assert.Len(t, list, 2)
	assert.Contains(t, list, "ctx1")
	assert.Contains(t, list, "ctx2")

	// Test Delete
	err = s.Delete("ctx1")
	assert.NoError(t, err)

	val, found = s.Get("ctx1", "token1")
	assert.False(t, found)

	count, err = s.Count("ctx1")
	assert.NoError(t, err)
	assert.Equal(t, 0, count)

	list, err = s.List()
	assert.NoError(t, err)
	assert.Len(t, list, 1)
	assert.Contains(t, list, "ctx2")
}

func TestInMemoryContextService_Hashing(t *testing.T) {
	s := NewInMemoryContextService()

	token := "my-secret-token"
	// Hashing is internal, so we don't test it directly here if it's not exported.
	// But we can check that it works through the public API.

	s.Put("ctx1", token, "repl")

	// Verify we can get it by original token
	val, found := s.Get("ctx1", token)
	assert.True(t, found)
	assert.Equal(t, "repl", val)
}
