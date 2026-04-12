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
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"time"

	"github.com/philterd/go-phileas/pkg/model"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// Entry represents an immutable redaction record in the ledger.
type Entry struct {
	DocumentId   string    `json:"document_id" bson:"document_id"`
	Text         string    `json:"text" bson:"text"`
	Replacement  string    `json:"replacement" bson:"replacement"`
	Start        int       `json:"start" bson:"start"`
	Stop         int       `json:"stop" bson:"stop"`
	FileName     string    `json:"file_name" bson:"file_name"`
	Timestamp    time.Time `json:"timestamp" bson:"timestamp"`
	PreviousHash []byte    `json:"previous_hash" bson:"previous_hash"`
}

// Ledger is an interface for recording and retrieving redaction entries in an immutable ledger.
type Ledger interface {
	Record(docID, fileName string, span model.Span, replacement string) error
	Get(docID string) ([]Entry, error)
}

func encrypt(text string, key []byte) (string, error) {
	if len(key) == 0 {
		return text, nil
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, aes.BlockSize+len(text))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(text))

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func decrypt(cryptoText string, key []byte) (string, error) {
	if len(key) == 0 {
		return cryptoText, nil
	}

	ciphertext, err := base64.StdEncoding.DecodeString(cryptoText)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	if len(ciphertext) < aes.BlockSize {
		return "", fmt.Errorf("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return string(ciphertext), nil
}

type memoryLedger struct {
	mu            sync.Mutex
	entries       []Entry
	lastHash      []byte
	encryptionKey []byte
}

func newMemoryLedger() *memoryLedger {
	var key []byte
	keyStr := os.Getenv("LEDGER_ENCRYPTION_KEY")
	if keyStr != "" {
		key = []byte(keyStr)
		// AES keys must be 16, 24, or 32 bytes
		if len(key) != 16 && len(key) != 24 && len(key) != 32 {
			log.Printf("Warning: LEDGER_ENCRYPTION_KEY must be 16, 24, or 32 bytes. Encryption disabled.")
			key = nil
		}
	}

	return &memoryLedger{
		entries:       make([]Entry, 0),
		lastHash:      make([]byte, 32), // Start with a zero hash for the first entry
		encryptionKey: key,
	}
}

func (l *memoryLedger) Record(docID, fileName string, span model.Span, replacement string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	encryptedText, err := encrypt(span.Text, l.encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt text: %w", err)
	}

	entry := Entry{
		DocumentId:   docID,
		Text:         encryptedText,
		Replacement:  replacement,
		Start:        span.CharacterStart,
		Stop:         span.CharacterEnd,
		FileName:     fileName,
		Timestamp:    time.Now(),
		PreviousHash: l.lastHash,
	}

	// Calculate current hash
	h := sha256.New()
	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("failed to marshal entry: %w", err)
	}
	h.Write(data)
	l.lastHash = h.Sum(nil)

	l.entries = append(l.entries, entry)
	return nil
}

func (l *memoryLedger) Get(docID string) ([]Entry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	var result []Entry
	for _, entry := range l.entries {
		if entry.DocumentId == docID {
			// Decrypt the text before returning
			decryptedText, err := decrypt(entry.Text, l.encryptionKey)
			if err != nil {
				// If decryption fails, we'll return the entry with original (encrypted) text or an error?
				// Returning an error is safer to avoid returning garbage.
				return nil, fmt.Errorf("failed to decrypt entry: %w", err)
			}
			entry.Text = decryptedText
			result = append(result, entry)
		}
	}
	return result, nil
}

type mongoLedger struct {
	collection    *mongo.Collection
	mu            sync.Mutex
	lastHash      []byte
	encryptionKey []byte
}

func newMongoLedger(uri, dbName, collectionName string) (*mongoLedger, error) {
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

	var key []byte
	keyStr := os.Getenv("LEDGER_ENCRYPTION_KEY")
	if keyStr != "" {
		key = []byte(keyStr)
		if len(key) != 16 && len(key) != 24 && len(key) != 32 {
			log.Printf("Warning: LEDGER_ENCRYPTION_KEY must be 16, 24, or 32 bytes. Encryption disabled.")
			key = nil
		}
	}

	l := &mongoLedger{
		collection:    coll,
		encryptionKey: key,
	}

	// Initialize lastHash from the latest entry in the database
	opts := options.FindOne().SetSort(bson.D{{Key: "timestamp", Value: -1}})
	var lastEntry Entry
	err = coll.FindOne(ctx, bson.M{}, opts).Decode(&lastEntry)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			l.lastHash = make([]byte, 32)
		} else {
			return nil, fmt.Errorf("failed to retrieve last entry from mongodb: %w", err)
		}
	} else {
		// Calculate the hash of the last entry
		h := sha256.New()
		data, err := json.Marshal(lastEntry)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal last entry: %w", err)
		}
		h.Write(data)
		l.lastHash = h.Sum(nil)
	}

	return l, nil
}

func (l *mongoLedger) Record(docID, fileName string, span model.Span, replacement string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	encryptedText, err := encrypt(span.Text, l.encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt text: %w", err)
	}

	entry := Entry{
		DocumentId:   docID,
		Text:         encryptedText,
		Replacement:  replacement,
		Start:        span.CharacterStart,
		Stop:         span.CharacterEnd,
		FileName:     fileName,
		Timestamp:    time.Now(),
		PreviousHash: l.lastHash,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = l.collection.InsertOne(ctx, entry)
	if err != nil {
		return fmt.Errorf("failed to insert entry into mongodb: %w", err)
	}

	// Calculate current hash for next record
	h := sha256.New()
	data, err := json.Marshal(entry)
	if err != nil {
		// This is critical if we want immutability, but here we'll just log
		log.Printf("Warning: failed to marshal entry for hashing: %v", err)
		return fmt.Errorf("failed to marshal entry for hashing: %w", err)
	}
	h.Write(data)
	l.lastHash = h.Sum(nil)

	return nil
}

func (l *mongoLedger) Get(docID string) ([]Entry, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{"document_id": docID}
	cursor, err := l.collection.Find(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to find entries in mongodb: %w", err)
	}
	defer cursor.Close(ctx)

	var entries []Entry
	if err := cursor.All(ctx, &entries); err != nil {
		return nil, fmt.Errorf("failed to decode entries from mongodb: %w", err)
	}

	// Decrypt texts
	for i := range entries {
		decryptedText, err := decrypt(entries[i].Text, l.encryptionKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt entry: %w", err)
		}
		entries[i].Text = decryptedText
	}

	return entries, nil
}
