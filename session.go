package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"time"
)

type SessionStore interface {
	Get(key string) (string, error)
	Set(key, value string, expiry time.Time) error
}

type CookieStore struct {
	req    *http.Request
	w      http.ResponseWriter
	secure bool
}

func (s *CookieStore) Get(key string) (string, error) {
	if cookie, err := s.req.Cookie("op-" + key); err == nil {
		return cookie.Value, nil
	} else {
		return "", err
	}
}

func (s *CookieStore) Set(key, value string, expiry time.Time) error {
	http.SetCookie(s.w, &http.Cookie{
		Name:     "op-" + key,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Expires:  expiry,
		Secure:   s.secure,
	})
	return nil
}

type EncryptedStore struct {
	key     []byte
	proxied SessionStore
}

func (s *EncryptedStore) Get(key string) (string, error) {
	if encrypted, err := s.proxied.Get(key); err == nil {
		return s.decrypt(encrypted)
	} else {
		return "", err
	}
}

func (s *EncryptedStore) Set(key, value string, expiry time.Time) error {
	if encrypted, err := s.encrypt(value); err == nil {
		return s.proxied.Set(key, encrypted, expiry)
	} else {
		return err
	}
}

func (s *EncryptedStore) encrypt(plain string) (string, error) {
	plainBytes := []byte(plain)

	block, err := aes.NewCipher(s.key)
	if err != nil {
		return "", err
	}

	// Put IV at the beginning
	cipherText := make([]byte, aes.BlockSize+len(plainBytes))
	iv := cipherText[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], plainBytes)

	return base64.URLEncoding.EncodeToString(cipherText), nil
}

func (s *EncryptedStore) decrypt(encrypted string) (string, error) {
	cipherText, err := base64.URLEncoding.DecodeString(encrypted)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(s.key)
	if err != nil {
		return "", err
	}

	if len(cipherText) < aes.BlockSize {
		return "", errors.New("Cipher text block size is too short")
	}

	// Read IV from the beginning
	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(cipherText, cipherText)

	return string(cipherText), nil
}
