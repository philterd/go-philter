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

package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestHandleHealth(t *testing.T) {
	gin.SetMode(gin.TestMode)

	original := Version
	defer func() { Version = original }()
	Version = "1.2.3"

	r := gin.Default()
	r.GET("/api/health", HandleHealth)

	req, _ := http.NewRequest(http.MethodGet, "/api/health", nil)
	resp := httptest.NewRecorder()
	r.ServeHTTP(resp, req)

	assert.Equal(t, http.StatusOK, resp.Code)

	var res map[string]any
	assert.NoError(t, json.Unmarshal(resp.Body.Bytes(), &res))
	assert.Equal(t, "UP", res["status"])
	assert.Equal(t, "1.2.3", res["applicationVersion"])
}

// The version is unset when the binary is built without the version ldflag.
func TestHandleHealthWithoutVersion(t *testing.T) {
	gin.SetMode(gin.TestMode)

	original := Version
	defer func() { Version = original }()
	Version = ""

	r := gin.Default()
	r.GET("/api/health", HandleHealth)

	req, _ := http.NewRequest(http.MethodGet, "/api/health", nil)
	resp := httptest.NewRecorder()
	r.ServeHTTP(resp, req)

	assert.Equal(t, http.StatusOK, resp.Code)

	var res map[string]any
	assert.NoError(t, json.Unmarshal(resp.Body.Bytes(), &res))
	assert.Equal(t, "unknown", res["applicationVersion"])
}

// The endpoint must be reachable without a token, so it is registered outside
// the authenticated /api group.
func TestHandleHealthIsUnauthenticated(t *testing.T) {
	gin.SetMode(gin.TestMode)

	originalAuthEnabled, originalToken := authEnabled, apiToken
	defer func() { authEnabled, apiToken = originalAuthEnabled, originalToken }()
	authEnabled, apiToken = true, "secret-token"

	r := gin.Default()
	api := r.Group("/api", AuthMiddleware())
	api.GET("/contexts", HandleListContexts)
	r.GET("/api/health", HandleHealth)

	// A route inside the group rejects an unauthenticated request.
	req, _ := http.NewRequest(http.MethodGet, "/api/contexts", nil)
	resp := httptest.NewRecorder()
	r.ServeHTTP(resp, req)
	assert.Equal(t, http.StatusUnauthorized, resp.Code)

	req, _ = http.NewRequest(http.MethodGet, "/api/health", nil)
	resp = httptest.NewRecorder()
	r.ServeHTTP(resp, req)
	assert.Equal(t, http.StatusOK, resp.Code)
}
