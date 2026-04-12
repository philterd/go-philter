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
	"testing"

	"github.com/philterd/go-phileas/pkg/policy"
	"github.com/stretchr/testify/assert"
)

func TestCustomInMemoryPolicyService(t *testing.T) {
	s := newCustomInMemoryPolicyService()

	p1 := &policy.Policy{}

	// Test Put and Get
	err := s.Put("p1", p1)
	assert.NoError(t, err)

	got, err := s.Get("p1")
	assert.NoError(t, err)
	assert.Equal(t, p1, got)

	// Test Get non-existent
	got, err = s.Get("non-existent")
	assert.NoError(t, err)
	assert.Nil(t, got)

	// Test List
	err = s.Put("p2", &policy.Policy{})
	assert.NoError(t, err)

	list, err := s.List()
	assert.NoError(t, err)
	assert.Len(t, list, 2)
	assert.Contains(t, list, "p1")
	assert.Contains(t, list, "p2")

	// Test Delete
	err = s.Delete("p1")
	assert.NoError(t, err)

	got, err = s.Get("p1")
	assert.NoError(t, err)
	assert.Nil(t, got)

	list, err = s.List()
	assert.NoError(t, err)
	assert.Len(t, list, 1)
	assert.Contains(t, list, "p2")
}
