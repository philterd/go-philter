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

package services

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/philterd/go-philter/internal/policy"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type PolicyService interface {
	Get(name string) (*policy.Policy, error)
	Put(name string, p *policy.Policy) error
	Delete(name string) error
	List() ([]string, error)
}

type customInMemoryPolicyService struct {
	mu       sync.RWMutex
	policies map[string]*policy.Policy
}

func NewCustomInMemoryPolicyService() *customInMemoryPolicyService {
	return &customInMemoryPolicyService{
		policies: make(map[string]*policy.Policy),
	}
}

func (s *customInMemoryPolicyService) Get(name string) (*policy.Policy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.policies[name]
	if !ok {
		return nil, nil
	}
	return p, nil
}

func (s *customInMemoryPolicyService) Put(name string, p *policy.Policy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policies[name] = p
	return nil
}

func (s *customInMemoryPolicyService) Delete(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.policies, name)
	return nil
}

func (s *customInMemoryPolicyService) List() ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	keys := make([]string, 0, len(s.policies))
	for k := range s.policies {
		keys = append(keys, k)
	}
	return keys, nil
}

type MongoDBPolicyService struct {
	client     *mongo.Client
	database   *mongo.Database
	collection *mongo.Collection
}

type PolicyRecord struct {
	Name   string         `bson:"name"`
	Policy *policy.Policy `bson:"policy"`
}

func NewMongoDBPolicyService(uri, dbName, collectionName string) (*MongoDBPolicyService, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	clientOpts := options.Client().ApplyURI(uri)
	client, err := mongo.Connect(clientOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to mongodb: %w", err)
	}

	if err := client.Ping(ctx, nil); err != nil {
		return nil, fmt.Errorf("failed to ping mongodb: %w", err)
	}

	db := client.Database(dbName)
	coll := db.Collection(collectionName)

	_, err = coll.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "name", Value: 1}},
		Options: options.Index().SetUnique(true),
	})
	if err != nil {
		log.Printf("Warning: failed to create unique index on name: %v", err)
	}

	return &MongoDBPolicyService{
		client:     client,
		database:   db,
		collection: coll,
	}, nil
}

func (s *MongoDBPolicyService) Get(name string) (*policy.Policy, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{"name": name}
	var record PolicyRecord
	err := s.collection.FindOne(ctx, filter).Decode(&record)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to find policy %s in mongodb: %w", name, err)
	}

	return record.Policy, nil
}

func (s *MongoDBPolicyService) Put(name string, p *policy.Policy) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{"name": name}
	update := bson.M{
		"$set": bson.M{
			"policy": p,
		},
	}
	opts := options.UpdateOne().SetUpsert(true)

	_, err := s.collection.UpdateOne(ctx, filter, update, opts)
	if err != nil {
		return fmt.Errorf("failed to upsert policy %s in mongodb: %w", name, err)
	}

	return nil
}

func (s *MongoDBPolicyService) Delete(name string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{"name": name}
	_, err := s.collection.DeleteOne(ctx, filter)
	if err != nil {
		return fmt.Errorf("failed to delete policy %s from mongodb: %w", name, err)
	}

	return nil
}

func (s *MongoDBPolicyService) List() ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var names []string
	err := s.collection.Distinct(ctx, "name", bson.M{}).Decode(&names)
	if err != nil {
		return nil, fmt.Errorf("failed to list policies from mongodb: %w", err)
	}

	return names, nil
}
