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
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/philterd/go-philter/internal/metrics"
	"github.com/philterd/go-philter/internal/model"
	"github.com/philterd/go-philter/internal/policy"
	"github.com/philterd/go-philter/internal/services"
)

func init() { Init() }

var (
	contextService services.ContextManager
	policyService  services.PolicyService
	ledger         services.Ledger
	authEnabled    bool
	apiToken       string
	Version        string
)

func Init() {
	authEnabled = os.Getenv("PHILTER_AUTH_ENABLED") != "false"
	apiToken = os.Getenv("PHILTER_API_TOKEN")

	log.Printf("Phileas version %s", Version)
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
		contextService, err = services.NewMongoDBContextService(mongoURI, dbName, contextCollectionName)
		if err != nil {
			log.Fatalf("Failed to initialize MongoDB context service: %v", err)
		}

		policyService, err = services.NewMongoDBPolicyService(mongoURI, dbName, policyCollectionName)
		if err != nil {
			log.Fatalf("Failed to initialize MongoDB policy service: %v", err)
		}

		ledgerCollectionName := os.Getenv("MONGO_LEDGER_COLLECTION")
		if ledgerCollectionName == "" {
			ledgerCollectionName = "ledger"
		}

		ledger, err = services.NewMongoLedger(mongoURI, dbName, ledgerCollectionName)
		if err != nil {
			log.Fatalf("Failed to initialize MongoDB ledger: %v", err)
		}
	} else {
		log.Println("Using InMemoryContextService and InMemoryPolicyService")
		contextService = services.NewInMemoryContextService()
		policyService = services.NewCustomInMemoryPolicyService()
		ledger = services.NewMemoryLedger()
	}
}

// GetContextService returns the context service.
func GetContextService() services.ContextManager {
	return contextService
}

func HandleFilter(c *gin.Context) {
	var req model.FilterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	docID := req.DocumentId
	if docID == "" {
		docID = uuid.New().String()
	}

	tokens := strings.Fields(req.Text)
	metrics.IncrementTokensReceived(len(tokens))

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

	metrics.IncrementRedactions(len(res.Spans))

	if req.Context != "" {
		for _, span := range res.Spans {
			contextService.Put(req.Context, span.Text, span.Replacement)
		}
	}

	if c.Query("ledger") != "" {
		for _, span := range res.Spans {
			if err := ledger.Record(docID, req.FileName, span, span.Replacement); err != nil {
				log.Printf("Error: failed to record redaction in ledger: %v", err)
			}
		}
	}

	res.DocumentId = docID

	c.JSON(http.StatusOK, res)
}

func HandleExplain(c *gin.Context) {
	var req model.FilterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	docID := req.DocumentId
	if docID == "" {
		docID = uuid.New().String()
	}

	tokens := strings.Fields(req.Text)
	metrics.IncrementTokensReceived(len(tokens))

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

	metrics.IncrementRedactions(len(spans))

	if req.Context != "" {
		for _, span := range spans {
			contextService.Put(req.Context, span.Text, span.Replacement)
		}
	}

	if c.Query("ledger") != "" {
		for _, span := range spans {
			if err := ledger.Record(docID, req.FileName, span, span.Replacement); err != nil {
				log.Printf("Error: failed to record redaction in ledger: %v", err)
			}
		}
	}

	c.JSON(http.StatusOK, model.ExplainResult{
		DocumentId: docID,
		Spans:      spans,
	})
}

func HandleGetLedger(c *gin.Context) {
	docID := c.Param("documentId")
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

func HandleVerifyLedger(c *gin.Context) {
	docID := c.Param("documentId")
	if docID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "documentId parameter is required"})
		return
	}

	ok, err := ledger.Verify(docID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to verify ledger: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"verified": ok})
}

func HandleDeleteContext(c *gin.Context) {
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

func HandleListContexts(c *gin.Context) {
	contexts, err := contextService.List()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list contexts: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, contexts)
}

func HandleGetContext(c *gin.Context) {
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

func HandleListPolicies(c *gin.Context) {
	policies, err := policyService.List()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list policies: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, policies)
}

func HandleGetPolicy(c *gin.Context) {
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

func HandleCreatePolicy(c *gin.Context) {
	var req model.PolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	p, err := policyService.Get(req.Name)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check existing policy: " + err.Error()})
		return
	}
	if p != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "policy already exists"})
		return
	}

	if err := policyService.Put(req.Name, req.Policy); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save policy: " + err.Error()})
		return
	}
	c.Status(http.StatusCreated)
}

func HandleUpdatePolicy(c *gin.Context) {
	name := c.Param("name")
	if name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "policy name is required"})
		return
	}

	var p policy.Policy
	if err := c.ShouldBindJSON(&p); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	existing, err := policyService.Get(name)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check existing policy: " + err.Error()})
		return
	}
	if existing == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "policy not found"})
		return
	}

	if err := policyService.Put(name, &p); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update policy: " + err.Error()})
		return
	}
	c.Status(http.StatusOK)
}

func HandleDeletePolicy(c *gin.Context) {
	name := c.Param("name")
	if err := policyService.Delete(name); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete policy: " + err.Error()})
		return
	}
	c.Status(http.StatusNoContent)
}

func AuthMiddleware() gin.HandlerFunc {
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
