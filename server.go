package main

import (
	"context"
	"crypto/tls"
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

type apiVersionRoundTripper struct {
	proxied    http.RoundTripper
	apiVersion string
}

func (t *apiVersionRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	query := req.URL.Query()
	query.Add("api-version", t.apiVersion)
	req.URL.RawQuery = query.Encode()
	return t.proxied.RoundTrip(req)
}

type Server struct {
	opts         *Options
	log          *zap.Logger
	ctx          context.Context
	httpClient   *http.Client
	oidcProvider *oidc.Provider
	oauthCfg     *oauth2.Config
	proxy        *httputil.ReverseProxy
}

func NewServer(opts *Options, logger *zap.Logger) (*Server, error) {
	httpClient := &http.Client{
		Transport: &apiVersionRoundTripper{http.DefaultTransport, "1.0"},
		Timeout:   time.Minute,
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
			InsecureSkipVerify: true, // TODO
		},
	}

	return &Server{
		opts:         opts,
		log:          logger,
		ctx:          ctx,
		httpClient:   httpClient,
		oidcProvider: oidcProvider,
		oauthCfg:     oauthCfg,
		proxy:        proxy,
	}, nil
}

func (s *Server) getSessionStore(w http.ResponseWriter, req *http.Request) SessionStore {
	return &CookieStore{req, w}
}

func (s *Server) authorize() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		session := s.getSessionStore(w, req)

		state := uuid.NewV4().String()
		if err := session.Set("state", state, time.Time{}); err != nil {
			http.Error(w, "Fail to save state", http.StatusInternalServerError)
			return
		}

		redirectUrl := s.oauthCfg.AuthCodeURL(state,
			oauth2.SetAuthURLParam("resource", s.opts.Resource),
			oauth2.SetAuthURLParam("response_type", "code"),
		)
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
			ClientID: s.opts.Resource,
		})
		accessToken, err := verifier.Verify(s.ctx, accessResp.AccessToken)
		if err != nil {
			s.log.Error("Invalid access token", zap.Error(err))
			http.Error(w, "Invalid access token", http.StatusInternalServerError)
			return
		}

		var claims struct {
			Name string `json:"name"`
			OID  string `json:"oid"`
		}
		if err = accessToken.Claims(&claims); err != nil {
			s.log.Error("Malformed claims", zap.Error(err))
			http.Error(w, "Malformed claims", http.StatusInternalServerError)
			return
		}

		s.log.Info("id token in access resp", zap.String("idToken", accessResp.Extra("id_token").(string)))
		s.log.Info("access token in access resp", zap.String("accessToken", accessResp.AccessToken))
		s.log.Info("claims", zap.String("name", claims.Name), zap.String("oid", claims.OID))

		session.Set("access", accessResp.AccessToken, accessResp.Expiry)

		http.Redirect(w, req, "/", http.StatusTemporaryRedirect)
	}
}

func (s *Server) index() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		session := s.getSessionStore(w, req)

		access, err := session.Get("access")
		if err != nil {
			s.log.Info("Cannot find access token in session. Redirect to auth page.", zap.Error(err))
			http.Redirect(w, req, "/oauth/authorize", http.StatusTemporaryRedirect)
			return
		}

		verifier := s.oidcProvider.Verifier(&oidc.Config{
			ClientID: s.opts.Resource,
		})
		_, err = verifier.Verify(s.ctx, access)
		if err != nil {
			s.log.Info("Invalid access token in session. Redirect to auth page.", zap.Error(err))
			http.Redirect(w, req, "/oauth/authorize", http.StatusTemporaryRedirect)
			return
		}

		req.Header.Add("Authorization", "Bearer "+access)

		s.proxy.ServeHTTP(w, req)
	}
}

func (s *Server) Listen() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth/authorize", s.authorize())
	mux.HandleFunc("/oauth/callback", s.callback())
	mux.HandleFunc("/", s.index())
	return http.ListenAndServe(":3000", mux)
}
