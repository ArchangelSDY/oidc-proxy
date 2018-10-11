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
			ClientID: s.opts.ClientId,
		})
		_, err = verifier.Verify(s.ctx, accessResp.Extra("id_token").(string))
		if err != nil {
			s.log.Error("Invalid id token", zap.Error(err))
			http.Error(w, "Invalid id token", http.StatusInternalServerError)
			return
		}

		session.Set("id", accessResp.Extra("id_token").(string), accessResp.Expiry)
		session.Set("access", accessResp.AccessToken, accessResp.Expiry)

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

		access, err := session.Get("access")
		if err != nil {
			s.log.Info("Cannot find access token in session. Redirect to auth page.", zap.Error(err))
			http.Redirect(w, req, "/oauth/authorize", http.StatusTemporaryRedirect)
			return
		}

		if s.opts.UpstreamAccessToken != "" {
			req.Header.Add("Authorization", "Bearer "+s.opts.UpstreamAccessToken)
		} else {
			req.Header.Add("Authorization", "Bearer "+access)
		}

		userContext, err := ParseUserContext(s.opts, idToken)
		if err != nil {
			s.log.Error("Malformed claims", zap.Error(err))
			http.Error(w, "Malformed claims", http.StatusForbidden)
			return
		}

		if s.opts.EnableImpersonation {
			req.Header.Add("Impersonate-User", userContext.UserName)
			for _, group := range userContext.Groups {
				s.log.Info("groups", zap.String("group", group))
				req.Header.Add("Impersonate-Group", group)
			}
		}

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
