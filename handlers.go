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
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/philterd/go-phileas/pkg/services"
)

var (
	contextService ContextManager
	policyService  PolicyService
	ledger         Ledger
	authEnabled    bool
	apiToken       string
)

func init() {
	authEnabled = os.Getenv("PHILTER_AUTH_ENABLED") != "false"
	apiToken = os.Getenv("PHILTER_API_TOKEN")

	log.Printf("Phileas version %s", version)
	mongoURI := os.Getenv("MONGO_URI")
	if mongoURI != "" {
		dbName := os.Getenv("MONGO_DATABASE")
		if dbName == "" {
			dbName = "philter"
		}
		contextCollectionName := "contexts"
		policyCollectionName := "policies"

		log.Printf("Connecting to MongoDB for services: %s", mongoURI)
		var err error
		contextService, err = NewMongoDBContextService(mongoURI, dbName, contextCollectionName)
		if err != nil {
			log.Fatalf("Failed to initialize MongoDB context service: %v", err)
		}

		policyService, err = NewMongoDBPolicyService(mongoURI, dbName, policyCollectionName)
		if err != nil {
			log.Fatalf("Failed to initialize MongoDB policy service: %v", err)
		}

		ledgerCollectionName := os.Getenv("MONGO_LEDGER_COLLECTION")
		if ledgerCollectionName == "" {
			ledgerCollectionName = "ledger"
		}

		ledger, err = newMongoLedger(mongoURI, dbName, ledgerCollectionName)
		if err != nil {
			log.Fatalf("Failed to initialize MongoDB ledger: %v", err)
		}
	} else {
		log.Println("Using InMemoryContextService and InMemoryPolicyService")
		contextService = newCustomInMemoryContextService()
		policyService = newCustomInMemoryPolicyService()
		ledger = newMemoryLedger()
	}
}

func handleFilter(c *gin.Context) {
	var req FilterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	tokens := strings.Fields(req.Text)
	incrementTokensReceived(len(tokens))

	p, err := policyService.Get(req.PolicyName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to retrieve policy: " + err.Error()})
		return
	}
	if p == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "policy not found: " + req.PolicyName})
		return
	}

	svc, err := services.NewFilterServiceWithContext(p, contextService)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to initialize filter service: " + err.Error()})
		return
	}

	res, err := svc.Filter(p, req.Context, req.Text)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "filtering failed: " + err.Error()})
		return
	}

	incrementRedactions(len(res.Spans))

	if req.Context != "" {
		for _, span := range res.Spans {
			contextService.Put(req.Context, span.Text, span.Replacement)
		}
	}

	for _, span := range res.Spans {
		if err := ledger.Record(req.DocumentId, req.FileName, span, span.Replacement); err != nil {
			log.Printf("Error: failed to record redaction in ledger: %v", err)
		}
	}

	c.JSON(http.StatusOK, res)
}

func handleExplain(c *gin.Context) {
	var req FilterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	tokens := strings.Fields(req.Text)
	incrementTokensReceived(len(tokens))

	p, err := policyService.Get(req.PolicyName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to retrieve policy: " + err.Error()})
		return
	}
	if p == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "policy not found: " + req.PolicyName})
		return
	}

	svc, err := services.NewFilterServiceWithContext(p, contextService)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to initialize filter service: " + err.Error()})
		return
	}

	spans, err := svc.Explain(p, req.Context, req.Text)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "explanation failed: " + err.Error()})
		return
	}

	incrementRedactions(len(spans))

	if req.Context != "" {
		for _, span := range spans {
			contextService.Put(req.Context, span.Text, span.Replacement)
		}
	}

	for _, span := range spans {
		if err := ledger.Record(req.DocumentId, req.FileName, span, span.Replacement); err != nil {
			log.Printf("Error: failed to record redaction in ledger: %v", err)
		}
	}

	c.JSON(http.StatusOK, spans)
}

func handleGetLedger(c *gin.Context) {
	docID := c.Query("documentId")
	if docID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "documentId parameter is required"})
		return
	}

	entries, err := ledger.Get(docID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to retrieve ledger entries: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, entries)
}

func handleDeleteContext(c *gin.Context) {
	contextName := c.Param("name")
	if contextName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "context name is required"})
		return
	}

	if err := contextService.Delete(contextName); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete context: " + err.Error()})
		return
	}

	c.Status(http.StatusNoContent)
}

func handleListContexts(c *gin.Context) {
	contexts, err := contextService.List()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list contexts: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, contexts)
}

func handleGetContext(c *gin.Context) {
	name := c.Param("name")
	if name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "context name is required"})
		return
	}

	count, err := contextService.Count(name)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to count context items: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"name": name, "count": count})
}

func handleListPolicies(c *gin.Context) {
	policies, err := policyService.List()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list policies: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, policies)
}

func handleGetPolicy(c *gin.Context) {
	name := c.Param("name")
	p, err := policyService.Get(name)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get policy: " + err.Error()})
		return
	}
	if p == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "policy not found"})
		return
	}
	c.JSON(http.StatusOK, p)
}

func handlePutPolicy(c *gin.Context) {
	var req PolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := policyService.Put(req.Name, req.Policy); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save policy: " + err.Error()})
		return
	}
	c.Status(http.StatusCreated)
}

func handleDeletePolicy(c *gin.Context) {
	name := c.Param("name")
	if err := policyService.Delete(name); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete policy: " + err.Error()})
		return
	}
	c.Status(http.StatusNoContent)
}

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !authEnabled {
			c.Next()
			return
		}

		if apiToken == "" {
			// If auth is enabled but no token is set, we might want to log a warning
			// or just let it through if it's meant to be "not yet configured".
			// However, the issue says "API token should be an environment variable".
			// Let's assume if enabled, a token MUST be provided.
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "API token not configured"})
			return
		}

		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization header is required"})
			return
		}

		const bearerPrefix = "Bearer "
		if len(authHeader) < len(bearerPrefix) || authHeader[:len(bearerPrefix)] != bearerPrefix {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization header must be a Bearer token"})
			return
		}

		token := authHeader[len(bearerPrefix):]
		if token != apiToken {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid API token"})
			return
		}

		c.Next()
	}
}
