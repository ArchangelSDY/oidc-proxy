package main

import (
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

type inMemoryStore struct {
	tbl map[string]string
}

func (s *inMemoryStore) Get(key string) (string, error) {
	if val, ok := s.tbl[key]; ok {
		return val, nil
	} else {
		return "", errors.New("Not found")
	}
}

func (s *inMemoryStore) Set(key, value string, expiry time.Time) error {
	s.tbl[key] = value
	return nil
}

func TestEncryptedStore(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		t.Fatal()
	}

	store := &EncryptedStore{key, &inMemoryStore{make(map[string]string)}}
	if err = store.Set("foo", "bar", time.Time{}); err != nil {
		t.Fatal(err)
	}

	if val, err := store.Get("foo"); err != nil {
		t.Fatal(err)
	} else if val != "bar" {
		t.Fatalf("expect %s but got %s", "bar", val)
	}
}
