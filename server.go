package main

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/coreos/go-oidc"
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

	return &Server{
		opts:         opts,
		log:          logger,
		ctx:          ctx,
		httpClient:   httpClient,
		oidcProvider: oidcProvider,
		oauthCfg:     oauthCfg,
	}, nil
}

func (s *Server) login() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		redirectUrl := s.oauthCfg.AuthCodeURL("state",
			oauth2.SetAuthURLParam("resource", s.opts.Resource),
			oauth2.SetAuthURLParam("response_type", "code"),
			oauth2.SetAuthURLParam("response_mode", "query"),
			oauth2.SetAuthURLParam("nonce", "aaabbbccc"),
		)
		http.Redirect(w, req, redirectUrl, http.StatusTemporaryRedirect)
	}
}

func (s *Server) callback() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
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

		code := query.Get("code")
		state := query.Get("state")

		s.log.Info("Auth callback", zap.String("id_token", query.Get("id_token")), zap.String("code", code), zap.String("state", state))

		accessResp, err := s.oauthCfg.Exchange(s.ctx, code)
		if err != nil {
			s.log.Error("Fail to exchange access code", zap.Error(err))
			http.Error(w, "Fail to exchange access code", http.StatusInternalServerError)
			return
		}

		verifier := s.oidcProvider.Verifier(&oidc.Config{
			ClientID: s.opts.Resource,
		})
		idToken, err := verifier.Verify(s.ctx, accessResp.AccessToken)
		if err != nil {
			s.log.Error("Invalid id token", zap.Error(err))
			http.Error(w, "Invalid id token", http.StatusInternalServerError)
			return
		}

		var claims struct {
			Name string `json:"name"`
			OID  string `json:"oid"`
		}
		if err = idToken.Claims(&claims); err != nil {
			s.log.Error("Malformed claims", zap.Error(err))
			http.Error(w, "Malformed claims", http.StatusInternalServerError)
			return
		}

		s.log.Info("claims", zap.String("name", claims.Name), zap.String("oid", claims.OID))

		encoder := json.NewEncoder(w)
		encoder.Encode(accessResp)
	}
}

func (s *Server) Listen() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth/login", s.login())
	mux.HandleFunc("/oauth/callback", s.callback())
	return http.ListenAndServe(":3000", mux)
}
