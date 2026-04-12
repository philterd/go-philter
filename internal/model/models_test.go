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

package model

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFilterRequest_JSON(t *testing.T) {
	jsonData := `{
		"text": "Hello world",
		"context": "test-context",
		"policy": "test-policy"
	}`

	var req FilterRequest
	err := json.Unmarshal([]byte(jsonData), &req)
	assert.NoError(t, err)

	assert.Equal(t, "Hello world", req.Text)
	assert.Equal(t, "test-context", req.Context)
	assert.Equal(t, "test-policy", req.PolicyName)
}

func TestFilterRequest_Validation(t *testing.T) {
	req := FilterRequest{}
	assert.Empty(t, req.Text)
	assert.Empty(t, req.Context)
	assert.Empty(t, req.PolicyName)
}

func TestPolicyRequest_JSON(t *testing.T) {
	jsonData := `{
		"name": "test-policy",
		"policy": {
			"identifiers": {
				"ssn": {
					"enabled": true
				}
			}
		}
	}`

	var req PolicyRequest
	err := json.Unmarshal([]byte(jsonData), &req)
	assert.NoError(t, err)

	assert.Equal(t, "test-policy", req.Name)
	assert.NotNil(t, req.Policy)
	assert.NotNil(t, req.Policy.Identifiers.SSN)
}
