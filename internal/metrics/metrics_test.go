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

package metrics

import (
	"net/http"
	"net/http/httptest"
	"testing"

	
	"github.com/gin-gonic/gin"
	"github.com/philterd/go-philter/internal/services"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
)

func TestPhilterHealthyMetric(t *testing.T) {
	// philterHealthy is a Gauge set to 1 in init()
	val := testutil.ToFloat64(philterHealthy)
	assert.Equal(t, 1.0, val)
}

func TestIncrementTokensReceived(t *testing.T) {
	initial := testutil.ToFloat64(philterTokensReceivedTotal)

	IncrementTokensReceived(5)

	final := testutil.ToFloat64(philterTokensReceivedTotal)
	assert.Equal(t, initial+5, final)
}

func TestIncrementRedactions(t *testing.T) {
	initial := testutil.ToFloat64(philterRedactionsTotal)

	IncrementRedactions(3)

	final := testutil.ToFloat64(philterRedactionsTotal)
	assert.Equal(t, initial+3, final)
}

func TestHandleMetricsEndpoint(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/metrics", HandleMetrics)

	// Increment metrics to ensure they appear in the output
	IncrementTokensReceived(10)
	IncrementRedactions(2)

	req, _ := http.NewRequest(http.MethodGet, "/metrics", nil)
	resp := httptest.NewRecorder()
	r.ServeHTTP(resp, req)

	assert.Equal(t, http.StatusOK, resp.Code)
	body := resp.Body.String()

	assert.Contains(t, body, "philter_healthy 1")
	assert.Contains(t, body, "philter_tokens_received_total")
	assert.Contains(t, body, "philter_redactions_total")
	assert.Contains(t, body, "philter_contexts_total")
}

func TestMetricsRegistry(t *testing.T) {
	// This test ensures that the metrics are actually registered with the default registry
	// which promhttp.Handler() uses.

	names := []string{
		"philter_healthy",
		"philter_tokens_received_total",
		"philter_redactions_total",
		"philter_contexts_total",
	}

	for _, name := range names {
		// testutil.CollectAndCount returns the number of metrics with the given name in the registry
		count, err := testutil.GatherAndCount(prometheus.DefaultGatherer, name)
		assert.NoError(t, err)
		assert.Equal(t, 1, count, "Metric %s should be registered", name)
	}
}

func TestPhilterContextsTotalMetric(t *testing.T) {
	// Initialize contextService if nil (it should be initialized in handlers.go init())
	if contextService == nil {
		contextService = services.NewInMemoryContextService()
	}

	// Add some contexts
	contextService.Put("ctx-metric-1", "t1", "r1")
	contextService.Put("ctx-metric-2", "t2", "r2")

	// testutil.ToFloat64 might be more convenient
	fval := testutil.ToFloat64(philterContextsTotal)
	assert.GreaterOrEqual(t, fval, 2.0)

	// Add another
	contextService.Put("ctx-metric-3", "t3", "r3")
	fval2 := testutil.ToFloat64(philterContextsTotal)
	assert.Equal(t, fval+1, fval2)

	// Delete
	contextService.Delete("ctx-metric-1")
	fval3 := testutil.ToFloat64(philterContextsTotal)
	assert.Equal(t, fval2-1, fval3)
}
