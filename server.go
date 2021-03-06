package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/satori/go.uuid"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

type Server struct {
	opts         *Options
	log          *zap.Logger
	ctx          context.Context
	httpClient   *http.Client
	oidcProvider *oidc.Provider
	oauthCfg     *oauth2.Config
	proxy        *httputil.ReverseProxy
	sessEncKey   []byte
}

func NewServer(opts *Options, logger *zap.Logger) (*Server, error) {
	httpClient := &http.Client{
		Timeout: time.Minute,
	}

	ctx := oidc.ClientContext(context.Background(), httpClient)
	oidcProvider, err := oidc.NewProvider(ctx, opts.IssuerURL)
	if err != nil {
		return nil, err
	}

	oauthCfg := &oauth2.Config{
		ClientID:     opts.ClientId,
		ClientSecret: opts.ClientSecret,
		Endpoint:     oidcProvider.Endpoint(),
		RedirectURL:  opts.RedirectURL,
		Scopes:       []string{"openid", "profile", "email"},
	}

	upstreamURL, err := url.Parse(opts.UpstreamURL)
	if err != nil {
		return nil, err
	}
	proxy := httputil.NewSingleHostReverseProxy(upstreamURL)
	proxy.Transport = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: opts.SkipVerifyUpstreamTLS,
		},
	}

	var sessEncKey []byte
	if opts.SessionEncryptionKey != "" {
		sessEncKey, err = base64.URLEncoding.DecodeString(opts.SessionEncryptionKey)
		if err != nil {
			return nil, err
		}
	}

	return &Server{
		opts:         opts,
		log:          logger,
		ctx:          ctx,
		httpClient:   httpClient,
		oidcProvider: oidcProvider,
		oauthCfg:     oauthCfg,
		proxy:        proxy,
		sessEncKey:   sessEncKey,
	}, nil
}

func (s *Server) getSessionStore(w http.ResponseWriter, req *http.Request) SessionStore {
	var store SessionStore = &CookieStore{req, w, s.opts.SecureCookie}
	if len(s.sessEncKey) > 0 {
		store = &EncryptedStore{s.sessEncKey, store}
	}
	return store
}

func (s *Server) authorize() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		session := s.getSessionStore(w, req)

		state := uuid.NewV4().String()
		if err := session.Set("state", state, time.Time{}); err != nil {
			http.Error(w, "Fail to save state", http.StatusInternalServerError)
			return
		}

		redirectUrl := s.oauthCfg.AuthCodeURL(state)

		http.Redirect(w, req, redirectUrl, http.StatusTemporaryRedirect)
	}
}

func (s *Server) callback() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		session := s.getSessionStore(w, req)
		state, err := session.Get("state")
		if err != nil {
			s.log.Warn("State not found", zap.Error(err))
			http.Error(w, "State not found", http.StatusForbidden)
			return
		}

		query := req.URL.Query()
		errCode := query.Get("error")

		if errCode != "" {
			errDescription := query.Get("error_description")
			s.log.Warn("Failed to auth",
				zap.String("error", errCode),
				zap.String("errorDescription", errDescription))
			http.Error(w, errDescription, http.StatusForbidden)
			return
		}

		if state != query.Get("state") {
			http.Error(w, "Invalid state", http.StatusForbidden)
			return
		}

		code := query.Get("code")

		accessResp, err := s.oauthCfg.Exchange(s.ctx, code)
		if err != nil {
			s.log.Error("Fail to exchange access code", zap.Error(err))
			http.Error(w, "Fail to exchange access code", http.StatusInternalServerError)
			return
		}

		verifier := s.oidcProvider.Verifier(&oidc.Config{
			ClientID: s.opts.ClientId,
		})
		_, err = verifier.Verify(s.ctx, accessResp.Extra("id_token").(string))
		if err != nil {
			s.log.Error("Invalid id token", zap.Error(err))
			http.Error(w, "Invalid id token", http.StatusInternalServerError)
			return
		}

		session.Set("id", accessResp.Extra("id_token").(string), accessResp.Expiry)

		http.Redirect(w, req, "/", http.StatusTemporaryRedirect)
	}
}

func (s *Server) index() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		session := s.getSessionStore(w, req)
		verifier := s.oidcProvider.Verifier(&oidc.Config{
			ClientID: s.opts.ClientId,
		})

		id, err := session.Get("id")
		if err != nil {
			s.log.Info("Cannot find id token in session. Redirect to auth page.", zap.Error(err))
			http.Redirect(w, req, "/oauth/authorize", http.StatusTemporaryRedirect)
			return
		}
		idToken, err := verifier.Verify(s.ctx, id)
		if err != nil {
			s.log.Info("Invalid id token in session. Redirect to auth page.", zap.Error(err))
			http.Redirect(w, req, "/oauth/authorize", http.StatusTemporaryRedirect)
			return
		}

		req.Header.Add("Authorization", "Bearer "+id)

		userContext, err := ParseUserContext(s.opts, idToken)
		if err != nil {
			s.log.Error("Malformed claims", zap.Error(err))
			http.Error(w, "Malformed claims", http.StatusForbidden)
			return
		}

		for _, header := range s.opts.UpstreamUserHeader {
			req.Header.Add(header, userContext.UserName)
		}

		for _, header := range s.opts.UpstreamGroupHeader {
			for _, group := range userContext.Groups {
				req.Header.Add(header, group)
			}
		}

		s.proxy.ServeHTTP(w, req)
	}
}

func (s *Server) Listen(addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth/authorize", s.authorize())
	mux.HandleFunc("/oauth/callback", s.callback())
	mux.HandleFunc("/", s.index())

	if s.opts.TLSCertFile != "" && s.opts.TLSKeyFile != "" {
		return http.ListenAndServeTLS(addr, s.opts.TLSCertFile, s.opts.TLSKeyFile, mux)
	} else {
		return http.ListenAndServe(addr, mux)
	}
}
