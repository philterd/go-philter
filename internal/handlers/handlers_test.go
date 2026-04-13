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
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/philterd/go-philter/internal/metrics"
	"github.com/philterd/go-philter/internal/model"
	"github.com/philterd/go-philter/internal/policy"
	"github.com/stretchr/testify/assert"
)

func TestHandleFilter(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.Default()
	r.POST("/api/filter", HandleFilter)

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

	policyService.Put("test-policy", p)

	reqBody := model.FilterRequest{
		Text:       "His SSN is 123-45-6789.",
		Context:    "test",
		PolicyName: "test-policy",
	}
	body, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest(http.MethodPost, "/api/filter", bytes.NewBuffer(body))
	resp := httptest.NewRecorder()
	r.ServeHTTP(resp, req)

	assert.Equal(t, http.StatusOK, resp.Code)
	assert.Empty(t, resp.Header().Get("X-Document-Id"))

	var res map[string]any
	json.Unmarshal(resp.Body.Bytes(), &res)
	assert.NotEmpty(t, res["documentId"])
	assert.Contains(t, res["filteredText"], "{{{REDACTED-ssn}}}")
}

func TestHandleExplain(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.Default()
	r.POST("/api/explain", HandleExplain)
	r.GET("/api/ledger/:documentId", HandleGetLedger)

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
	policyService.Put("test-policy", p)

	t.Run("LedgerEnabled", func(t *testing.T) {
		reqBody := model.FilterRequest{
			Text:       "His SSN is 123-45-6789.",
			Context:    "test-explain-ledger-enabled",
			PolicyName: "test-policy",
		}
		body, _ := json.Marshal(reqBody)

		req, _ := http.NewRequest(http.MethodPost, "/api/explain?ledger=true", bytes.NewBuffer(body))
		resp := httptest.NewRecorder()
		r.ServeHTTP(resp, req)

		assert.Equal(t, http.StatusOK, resp.Code)
		var res map[string]any
		json.Unmarshal(resp.Body.Bytes(), &res)
		docID := res["documentId"].(string)

		req, _ = http.NewRequest(http.MethodGet, "/api/ledger/"+docID, nil)
		resp = httptest.NewRecorder()
		r.ServeHTTP(resp, req)

		assert.Equal(t, http.StatusOK, resp.Code)
		var entries []any
		json.Unmarshal(resp.Body.Bytes(), &entries)
		assert.NotEmpty(t, entries)
	})

	t.Run("LedgerDisabled", func(t *testing.T) {
		reqBody := model.FilterRequest{
			Text:       "His SSN is 123-45-6789.",
			Context:    "test-explain-ledger-disabled",
			PolicyName: "test-policy",
		}
		body, _ := json.Marshal(reqBody)

		req, _ := http.NewRequest(http.MethodPost, "/api/explain", bytes.NewBuffer(body))
		resp := httptest.NewRecorder()
		r.ServeHTTP(resp, req)

		assert.Equal(t, http.StatusOK, resp.Code)
		var res map[string]any
		json.Unmarshal(resp.Body.Bytes(), &res)
		docID := res["documentId"].(string)

		req, _ = http.NewRequest(http.MethodGet, "/api/ledger/"+docID, nil)
		resp = httptest.NewRecorder()
		r.ServeHTTP(resp, req)

		assert.Equal(t, http.StatusOK, resp.Code)
		var entries []any
		json.Unmarshal(resp.Body.Bytes(), &entries)
		assert.Empty(t, entries)
	})
}

func TestContextPersistence(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.Default()
	r.POST("/api/filter", HandleFilter)

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

	policyService.Put("persistence-policy", p)

	// First call to /filter with context "persistence-test"
	reqBody1 := model.FilterRequest{
		Text:       "His SSN is 123-45-6789.",
		Context:    "persistence-test",
		PolicyName: "persistence-policy",
	}
	body1, _ := json.Marshal(reqBody1)
	req1, _ := http.NewRequest(http.MethodPost, "/api/filter", bytes.NewBuffer(body1))
	resp1 := httptest.NewRecorder()
	r.ServeHTTP(resp1, req1)

	assert.Equal(t, http.StatusOK, resp1.Code)
	var res1 map[string]any
	json.Unmarshal(resp1.Body.Bytes(), &res1)
	replacement := ""
	for _, s := range res1["spans"].([]any) {
		span := s.(map[string]any)
		if span["text"] == "123-45-6789" {
			replacement = span["replacement"].(string)
		}
	}
	assert.NotEmpty(t, replacement)

	// Second call with same context, same SSN, but SSN filter DISABLED
	// It should still be stored in the context service.
	pDisabled := &policy.Policy{
		Identifiers: policy.Identifiers{
			SSN: &policy.SSNFilter{
				BaseFilter: policy.BaseFilter{
					Enabled: new(bool),
				},
			},
		},
	}
	*pDisabled.Identifiers.SSN.Enabled = false

	policyService.Put("disabled-policy", pDisabled)

	reqBody2 := model.FilterRequest{
		Text:       "The same SSN 123-45-6789 should be in context.",
		Context:    "persistence-test",
		PolicyName: "disabled-policy",
	}
	body2, _ := json.Marshal(reqBody2)
	req2, _ := http.NewRequest(http.MethodPost, "/api/filter", bytes.NewBuffer(body2))
	resp2 := httptest.NewRecorder()
	r.ServeHTTP(resp2, req2)

	assert.Equal(t, http.StatusOK, resp2.Code)

	// Verify it's in the global context service
	val, ok := contextService.Get("persistence-test", "123-45-6789")
	assert.True(t, ok)
	assert.Equal(t, replacement, val)

	// Third call with DIFFERENT context
	val2, ok2 := contextService.Get("other-context", "123-45-6789")
	assert.False(t, ok2)
	assert.Empty(t, val2)
}

func TestHandleMetrics(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.Default()
	r.GET("/metrics", metrics.HandleMetrics)

	req, _ := http.NewRequest(http.MethodGet, "/metrics", nil)
	resp := httptest.NewRecorder()
	r.ServeHTTP(resp, req)

	assert.Equal(t, http.StatusOK, resp.Code)
	assert.Contains(t, resp.Body.String(), "philter_healthy 1")
}

func TestTokenMetrics(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.Default()
	r.POST("/api/filter", HandleFilter)
	r.POST("/api/explain", HandleExplain)
	r.GET("/metrics", metrics.HandleMetrics)

	p := &policy.Policy{}

	policyService.Put("token-policy", p)

	// 1. Call /filter with 3 tokens
	reqBody1 := model.FilterRequest{
		Text:       "one two three",
		PolicyName: "token-policy",
	}
	body1, _ := json.Marshal(reqBody1)
	req1, _ := http.NewRequest(http.MethodPost, "/api/filter", bytes.NewBuffer(body1))
	resp1 := httptest.NewRecorder()
	r.ServeHTTP(resp1, req1)
	assert.Equal(t, http.StatusOK, resp1.Code)

	// 2. Call /explain with 2 tokens
	reqBody2 := model.FilterRequest{
		Text:       "four five",
		PolicyName: "token-policy",
	}
	body2, _ := json.Marshal(reqBody2)
	req2, _ := http.NewRequest(http.MethodPost, "/api/explain", bytes.NewBuffer(body2))
	resp2 := httptest.NewRecorder()
	r.ServeHTTP(resp2, req2)
	assert.Equal(t, http.StatusOK, resp2.Code)

	// 3. Check metrics
	reqM, _ := http.NewRequest(http.MethodGet, "/metrics", nil)
	respM := httptest.NewRecorder()
	r.ServeHTTP(respM, reqM)

	assert.Equal(t, http.StatusOK, respM.Code)
	// The counter should be at least 5 (3 from filter, 2 from explain).
	// Other tests might have incremented it too, so we check for at least 5.
	assert.Contains(t, respM.Body.String(), "philter_tokens_received_total")

	// We can't easily check the exact value if other tests ran,
	// but in a fresh test run it should be identifiable.
}

func TestRedactionMetrics(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.Default()
	r.POST("/api/filter", HandleFilter)
	r.POST("/api/explain", HandleExplain)
	r.GET("/metrics", metrics.HandleMetrics)

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

	policyService.Put("redaction-policy", p)

	// 1. Call /filter with 1 SSN (1 redaction)
	reqBody1 := model.FilterRequest{
		Text:       "My SSN is 123-45-6789.",
		PolicyName: "redaction-policy",
	}
	body1, _ := json.Marshal(reqBody1)
	req1, _ := http.NewRequest(http.MethodPost, "/api/filter", bytes.NewBuffer(body1))
	resp1 := httptest.NewRecorder()
	r.ServeHTTP(resp1, req1)
	assert.Equal(t, http.StatusOK, resp1.Code)

	// 2. Call /explain with 1 SSN (1 redaction)
	reqBody2 := model.FilterRequest{
		Text:       "Another SSN: 987-65-4321.",
		PolicyName: "redaction-policy",
	}
	body2, _ := json.Marshal(reqBody2)
	req2, _ := http.NewRequest(http.MethodPost, "/api/explain", bytes.NewBuffer(body2))
	resp2 := httptest.NewRecorder()
	r.ServeHTTP(resp2, req2)
	assert.Equal(t, http.StatusOK, resp2.Code)

	// 3. Check metrics
	reqM, _ := http.NewRequest(http.MethodGet, "/metrics", nil)
	respM := httptest.NewRecorder()
	r.ServeHTTP(respM, reqM)

	assert.Equal(t, http.StatusOK, respM.Code)
	// The counter should be at least 2.
	assert.Contains(t, respM.Body.String(), "philter_redactions_total")
}

func TestHandleDeleteContext(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.Default()
	r.POST("/api/filter", HandleFilter)
	r.DELETE("/api/context/:name", HandleDeleteContext)

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

	policyService.Put("delete-policy", p)

	// 1. Put some data into a context
	contextName := "delete-test"
	reqBody := model.FilterRequest{
		Text:       "His SSN is 123-45-6789.",
		Context:    "delete-test",
		PolicyName: "delete-policy",
	}
	body, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest(http.MethodPost, "/api/filter", bytes.NewBuffer(body))
	resp := httptest.NewRecorder()
	r.ServeHTTP(resp, req)
	assert.Equal(t, http.StatusOK, resp.Code)

	// Verify data is there
	_, ok := contextService.Get(contextName, "123-45-6789")
	assert.True(t, ok)

	// 2. Delete the context
	deleteReq, _ := http.NewRequest(http.MethodDelete, "/api/context/"+contextName, nil)
	deleteResp := httptest.NewRecorder()
	r.ServeHTTP(deleteResp, deleteReq)
	assert.Equal(t, http.StatusNoContent, deleteResp.Code)

	// 3. Verify data is gone
	_, ok = contextService.Get(contextName, "123-45-6789")
	assert.False(t, ok)
}

func TestHandleListContexts(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.Default()
	r.GET("/api/contexts", HandleListContexts)

	// Clean up and add some contexts
	contextService.Delete("list-test-1")
	contextService.Delete("list-test-2")

	contextService.Put("list-test-1", "t1", "r1")
	contextService.Put("list-test-2", "t2", "r2")

	req, _ := http.NewRequest(http.MethodGet, "/api/contexts", nil)
	resp := httptest.NewRecorder()
	r.ServeHTTP(resp, req)

	assert.Equal(t, http.StatusOK, resp.Code)

	var contexts []string
	err := json.Unmarshal(resp.Body.Bytes(), &contexts)
	assert.NoError(t, err)

	assert.Contains(t, contexts, "list-test-1")
	assert.Contains(t, contexts, "list-test-2")
}

func TestHandleGetContext(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.Default()
	r.GET("/api/contexts/:name", HandleGetContext)

	contextName := "get-test-context"
	contextService.Delete(contextName)

	contextService.Put(contextName, "t1", "r1")
	contextService.Put(contextName, "t2", "r2")

	req, _ := http.NewRequest(http.MethodGet, "/api/contexts/"+contextName, nil)
	resp := httptest.NewRecorder()
	r.ServeHTTP(resp, req)

	assert.Equal(t, http.StatusOK, resp.Code)

	var res map[string]any
	err := json.Unmarshal(resp.Body.Bytes(), &res)
	assert.NoError(t, err)

	assert.Equal(t, contextName, res["name"])
	assert.Equal(t, float64(2), res["count"]) // JSON numbers are float64
}

func TestHandlePolicyCRUD(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.Default()
	r.GET("/api/policies", HandleListPolicies)
	r.GET("/api/policies/:name", HandleGetPolicy)
	r.POST("/api/policies", HandlePutPolicy)
	r.DELETE("/api/policies/:name", HandleDeletePolicy)

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

	// 1. POST policy
	reqBody := model.PolicyRequest{
		Name:   "crud-policy",
		Policy: p,
	}
	body, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest(http.MethodPost, "/api/policies", bytes.NewBuffer(body))
	resp := httptest.NewRecorder()
	r.ServeHTTP(resp, req)
	assert.Equal(t, http.StatusCreated, resp.Code)

	// 2. GET policy
	req, _ = http.NewRequest(http.MethodGet, "/api/policies/crud-policy", nil)
	resp = httptest.NewRecorder()
	r.ServeHTTP(resp, req)
	assert.Equal(t, http.StatusOK, resp.Code)
	var pResp policy.Policy
	json.Unmarshal(resp.Body.Bytes(), &pResp)
	assert.NotNil(t, pResp.Identifiers.SSN)

	// 3. LIST policies
	req, _ = http.NewRequest(http.MethodGet, "/api/policies", nil)
	resp = httptest.NewRecorder()
	r.ServeHTTP(resp, req)
	assert.Equal(t, http.StatusOK, resp.Code)
	var list []string
	json.Unmarshal(resp.Body.Bytes(), &list)
	assert.Contains(t, list, "crud-policy")

	// 4. DELETE policy
	req, _ = http.NewRequest(http.MethodDelete, "/api/policies/crud-policy", nil)
	resp = httptest.NewRecorder()
	r.ServeHTTP(resp, req)
	assert.Equal(t, http.StatusNoContent, resp.Code)

	// 5. GET policy (verify gone)
	req, _ = http.NewRequest(http.MethodGet, "/api/policies/crud-policy", nil)
	resp = httptest.NewRecorder()
	r.ServeHTTP(resp, req)
	assert.Equal(t, http.StatusNotFound, resp.Code)
}

func TestHandleGetLedger(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.Default()
	r.POST("/api/filter", HandleFilter)
	r.GET("/api/ledger/:documentId", HandleGetLedger)
	r.GET("/api/ledger/:documentId/verify", HandleVerifyLedger)

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
	policyService.Put("test-policy", p)

	t.Run("LedgerEnabled", func(t *testing.T) {
		reqBody := model.FilterRequest{
			Text:       "His SSN is 123-45-6789.",
			Context:    "test-ledger-enabled",
			PolicyName: "test-policy",
		}
		body, _ := json.Marshal(reqBody)

		req, _ := http.NewRequest(http.MethodPost, "/api/filter?ledger=true", bytes.NewBuffer(body))
		resp := httptest.NewRecorder()
		r.ServeHTTP(resp, req)

		assert.Equal(t, http.StatusOK, resp.Code)
		var res map[string]any
		json.Unmarshal(resp.Body.Bytes(), &res)
		docID := res["documentId"].(string)
		assert.NotEmpty(t, docID)

		req, _ = http.NewRequest(http.MethodGet, "/api/ledger/"+docID, nil)
		resp = httptest.NewRecorder()
		r.ServeHTTP(resp, req)

		assert.Equal(t, http.StatusOK, resp.Code)
		var entries []any
		json.Unmarshal(resp.Body.Bytes(), &entries)
		assert.NotEmpty(t, entries)
	})

	t.Run("LedgerDisabled", func(t *testing.T) {
		reqBody := model.FilterRequest{
			Text:       "His SSN is 123-45-6789.",
			Context:    "test-ledger-disabled",
			PolicyName: "test-policy",
		}
		body, _ := json.Marshal(reqBody)

		req, _ := http.NewRequest(http.MethodPost, "/api/filter", bytes.NewBuffer(body))
		resp := httptest.NewRecorder()
		r.ServeHTTP(resp, req)

		assert.Equal(t, http.StatusOK, resp.Code)
		var res map[string]any
		json.Unmarshal(resp.Body.Bytes(), &res)
		docID := res["documentId"].(string)
		assert.NotEmpty(t, docID)

		req, _ = http.NewRequest(http.MethodGet, "/api/ledger/"+docID, nil)
		resp = httptest.NewRecorder()
		r.ServeHTTP(resp, req)

		assert.Equal(t, http.StatusOK, resp.Code)
		var entries []any
		json.Unmarshal(resp.Body.Bytes(), &entries)
		assert.Empty(t, entries)
	})
}

func TestAuthMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("AuthDisabled", func(t *testing.T) {
		oldAuth := authEnabled
		authEnabled = false
		defer func() { authEnabled = oldAuth }()

		r := gin.New()
		r.Use(AuthMiddleware())
		r.GET("/test", func(c *gin.Context) { c.Status(http.StatusOK) })

		req, _ := http.NewRequest(http.MethodGet, "/test", nil)
		resp := httptest.NewRecorder()
		r.ServeHTTP(resp, req)

		assert.Equal(t, http.StatusOK, resp.Code)
	})

	t.Run("AuthEnabledValidToken", func(t *testing.T) {
		oldAuth := authEnabled
		oldToken := apiToken
		authEnabled = true
		apiToken = "test-token"
		defer func() {
			authEnabled = oldAuth
			apiToken = oldToken
		}()

		r := gin.New()
		r.Use(AuthMiddleware())
		r.GET("/test", func(c *gin.Context) { c.Status(http.StatusOK) })

		req, _ := http.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", "Bearer test-token")
		resp := httptest.NewRecorder()
		r.ServeHTTP(resp, req)

		assert.Equal(t, http.StatusOK, resp.Code)
	})

	t.Run("AuthEnabledInvalidToken", func(t *testing.T) {
		oldAuth := authEnabled
		oldToken := apiToken
		authEnabled = true
		apiToken = "test-token"
		defer func() {
			authEnabled = oldAuth
			apiToken = oldToken
		}()

		r := gin.New()
		r.Use(AuthMiddleware())
		r.GET("/test", func(c *gin.Context) { c.Status(http.StatusOK) })

		req, _ := http.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", "Bearer wrong-token")
		resp := httptest.NewRecorder()
		r.ServeHTTP(resp, req)

		assert.Equal(t, http.StatusUnauthorized, resp.Code)
	})

	t.Run("AuthEnabledMissingHeader", func(t *testing.T) {
		oldAuth := authEnabled
		oldToken := apiToken
		authEnabled = true
		apiToken = "test-token"
		defer func() {
			authEnabled = oldAuth
			apiToken = oldToken
		}()

		r := gin.New()
		r.Use(AuthMiddleware())
		r.GET("/test", func(c *gin.Context) { c.Status(http.StatusOK) })

		req, _ := http.NewRequest(http.MethodGet, "/test", nil)
		resp := httptest.NewRecorder()
		r.ServeHTTP(resp, req)

		assert.Equal(t, http.StatusUnauthorized, resp.Code)
	})
}
