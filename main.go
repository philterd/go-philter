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
	"os"

	"github.com/gin-gonic/gin"
)

var version = "development"

func main() {
	r := gin.Default()

	api := r.Group("/api", authMiddleware())
	{
		api.POST("/filter", handleFilter)
		api.POST("/explain", handleExplain)
		api.DELETE("/contexts/:name", handleDeleteContext)
		api.GET("/contexts", handleListContexts)
		api.GET("/contexts/:name", handleGetContext)
		api.GET("/policies", handleListPolicies)
		api.GET("/policies/:name", handleGetPolicy)
		api.POST("/policies", handlePutPolicy)
		api.DELETE("/policies/:name", handleDeletePolicy)
	}

	r.GET("/metrics", handleMetrics)

	certFile := os.Getenv("PHILTER_CERT_FILE")
	keyFile := os.Getenv("PHILTER_KEY_FILE")

	if certFile != "" && keyFile != "" {
		log.Printf("Starting HTTPS server on :8080")
		log.Fatal(r.RunTLS(":8080", certFile, keyFile))
	} else {
		log.Printf("Starting HTTP server on :8080")
		log.Fatal(r.Run(":8080"))
	}
}
