package main

import (
	"net/http"
	"time"
)

type SessionStore interface {
	Get(key string) (string, error)
	Set(key, value string, expiry time.Time) error
}

type CookieStore struct {
	req *http.Request
	w   http.ResponseWriter
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
		// TODO: Secure: true,
	})
	return nil
}
