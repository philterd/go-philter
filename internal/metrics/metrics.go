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
	"github.com/gin-gonic/gin"
	"github.com/philterd/go-philter/internal/services"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	contextService services.ContextManager

	philterHealthy = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "philter_healthy",
		Help: "A boolean indicating Philter is healthy.",
	})

	philterTokensReceivedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "philter_tokens_received_total",
		Help: "The number of tokens received by the /filter and /explain endpoints.",
	})

	philterRedactionsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "philter_redactions_total",
		Help: "The total number of redactions performed by the /filter and /explain endpoints.",
	})

	philterContextsTotal = promauto.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "philter_contexts_total",
		Help: "The total number of contexts.",
	}, func() float64 {
		if contextService == nil {
			return 0
		}
		contexts, err := contextService.List()
		if err != nil {
			return 0
		}
		return float64(len(contexts))
	})
)

func init() {
	// For now, Philter is always healthy if the app is running.
	philterHealthy.Set(1)
}

// SetContextService sets the context service to be used for metrics.
func SetContextService(cs services.ContextManager) {
	contextService = cs
}

// HandleMetrics is the Gin handler for Prometheus metrics.
func HandleMetrics(c *gin.Context) {
	promhttp.Handler().ServeHTTP(c.Writer, c.Request)
}

// IncrementTokensReceived increments the tokens received counter.
func IncrementTokensReceived(count int) {
	philterTokensReceivedTotal.Add(float64(count))
}

// IncrementRedactions increments the redactions counter.
func IncrementRedactions(count int) {
	philterRedactionsTotal.Add(float64(count))
}
