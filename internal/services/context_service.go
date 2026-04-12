// Copyright 2026 Philterd, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// ContextService stores PII tokens and their replacement values to establish
// referential integrity while redacting text. The store is keyed by context
// name, and each context holds a map of token → replacement.
type ContextService interface {
	// Get returns the replacement for the given token in the given context.
	// The second return value is false when no entry exists.
	Get(ctxName, token string) (string, bool)

	// Put stores a token → replacement mapping under the given context.
	Put(ctxName, token, replacement string)
}

// ContextManager extends ContextService with Delete, List, and Count methods.
type ContextManager interface {
	ContextService
	Delete(ctxName string) error
	List() ([]string, error)
	Count(ctxName string) (int, error)
}

// InMemoryContextService is the default ContextService implementation that
// keeps all data in an in-memory map of maps.
type InMemoryContextService struct {
	mu    sync.RWMutex
	store map[string]map[string]string
}

// NewInMemoryContextService creates a new, empty InMemoryContextService.
func NewInMemoryContextService() *InMemoryContextService {
	return &InMemoryContextService{
		store: make(map[string]map[string]string),
	}
}

func hashToken(token string) string {
	h := sha256.New()
	h.Write([]byte(token))
	return hex.EncodeToString(h.Sum(nil))
}

// Get returns the replacement for the given token in the given context.
func (s *InMemoryContextService) Get(ctxName, token string) (string, bool) {
	hashedToken := hashToken(token)
	s.mu.RLock()
	defer s.mu.RUnlock()
	if ctx, ok := s.store[ctxName]; ok {
		replacement, found := ctx[hashedToken]
		return replacement, found
	}
	return "", false
}

// Put stores a token → replacement mapping under the given context.
func (s *InMemoryContextService) Put(ctxName, token, replacement string) {
	hashedToken := hashToken(token)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.store[ctxName]; !ok {
		s.store[ctxName] = make(map[string]string)
	}
	s.store[ctxName][hashedToken] = replacement
}

// Delete removes all entries for the given context.
func (s *InMemoryContextService) Delete(ctxName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.store, ctxName)
	return nil
}

// List returns the names of all contexts.
func (s *InMemoryContextService) List() ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	keys := make([]string, 0, len(s.store))
	for k := range s.store {
		keys = append(keys, k)
	}
	return keys, nil
}

// Count returns the number of entries in the given context.
func (s *InMemoryContextService) Count(ctxName string) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if ctx, ok := s.store[ctxName]; ok {
		return len(ctx), nil
	}
	return 0, nil
}

// MongoDBContextService is a ContextService implementation that uses MongoDB for storage.
type MongoDBContextService struct {
	client     *mongo.Client
	database   *mongo.Database
	collection *mongo.Collection
}

// ContextRecord represents a single context entry in MongoDB.
type ContextRecord struct {
	Context     string `bson:"context"`
	Token       string `bson:"token"`
	Replacement string `bson:"replacement"`
}

// NewMongoDBContextService creates a new MongoDBContextService.
func NewMongoDBContextService(uri, dbName, collectionName string) (*MongoDBContextService, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	clientOpts := options.Client().ApplyURI(uri)
	client, err := mongo.Connect(clientOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to mongodb: %w", err)
	}

	// Ping the database to verify the connection
	if err := client.Ping(ctx, nil); err != nil {
		return nil, fmt.Errorf("failed to ping mongodb: %w", err)
	}

	db := client.Database(dbName)
	coll := db.Collection(collectionName)

	_, err = coll.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "context", Value: 1}, {Key: "token", Value: 1}},
		Options: options.Index().SetUnique(true),
	})
	if err != nil {
		log.Printf("Warning: failed to create unique index on context and token: %v", err)
	}

	return &MongoDBContextService{
		client:     client,
		database:   db,
		collection: coll,
	}, nil
}

// Get returns the replacement for the given token in the given context from MongoDB.
func (s *MongoDBContextService) Get(ctxName, token string) (string, bool) {
	hashedToken := hashToken(token)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{
		"context": ctxName,
		"token":   hashedToken,
	}

	var record ContextRecord
	err := s.collection.FindOne(ctx, filter).Decode(&record)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return "", false
		}
		log.Printf("Error: failed to find document in mongodb: %v", err)
		return "", false
	}

	return record.Replacement, true
}

// Put stores a token → replacement mapping under the given context in MongoDB.
func (s *MongoDBContextService) Put(ctxName, token, replacement string) {
	hashedToken := hashToken(token)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{
		"context": ctxName,
		"token":   hashedToken,
	}

	update := bson.M{
		"$set": bson.M{
			"replacement": replacement,
		},
	}

	opts := options.UpdateOne().SetUpsert(true)

	_, err := s.collection.UpdateOne(ctx, filter, update, opts)
	if err != nil {
		log.Printf("Error: failed to upsert document in mongodb: %v", err)
	}
}

// Delete removes all entries for the given context from MongoDB.
func (s *MongoDBContextService) Delete(ctxName string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{
		"context": ctxName,
	}

	_, err := s.collection.DeleteMany(ctx, filter)
	if err != nil {
		return fmt.Errorf("failed to delete documents for context %s from mongodb: %w", ctxName, err)
	}

	return nil
}

// List returns the names of all contexts from MongoDB.
func (s *MongoDBContextService) List() ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var contexts []string
	err := s.collection.Distinct(ctx, "context", bson.M{}).Decode(&contexts)
	if err != nil {
		return nil, fmt.Errorf("failed to list contexts from mongodb: %w", err)
	}

	return contexts, nil
}

// Count returns the number of entries in the given context from MongoDB.
func (s *MongoDBContextService) Count(ctxName string) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{"context": ctxName}
	count, err := s.collection.CountDocuments(ctx, filter)
	if err != nil {
		return 0, fmt.Errorf("failed to count documents for context %s from mongodb: %w", ctxName, err)
	}

	return int(count), nil
}
