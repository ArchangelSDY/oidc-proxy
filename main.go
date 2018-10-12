package main

import (
	flags "github.com/jessevdk/go-flags"
	"go.uber.org/zap"
)

type Options struct {
	ClientId            string   `long:"client-id"`
	ClientSecret        string   `long:"client-secret"`
	IssuerURL           string   `long:"issuer-url"`
	Resource            string   `long:"resource"`
	RedirectURL         string   `long:"redirect-url"`
	TLSCertFile         string   `long:"tls-cert"`
	TLSKeyFile          string   `long:"tls-key"`
	UpstreamURL         string   `long:"upstream-url"`
	UpstreamAccessToken string   `long:"upstream-access-token"`
	UpstreamUserHeader  []string `long:"upstream-user-header"`
	UpstreamGroupHeader []string `long:"upstream-group-header"`
	UserPrefix          string   `long:"user-prefix"`
	UserClaim           string   `long:"user-claim"`
	GroupsPrefix        string   `long:"group-prefix"`
	GroupsClaim         string   `long:"groups-claim"`
}

func main() {
	logger, err := zap.NewDevelopment()
	if err != nil {
		panic(err)
	}
	defer logger.Sync()

	var opts Options
	if _, err = flags.Parse(&opts); err != nil {
		return
	}

	logger.Info("Listening...")

	server, err := NewServer(&opts, logger)
	if err != nil {
		logger.Fatal("Fail to initialize server", zap.Error(err))
	}

	if err = server.Listen(); err != nil {
		logger.Fatal("Fail to serve", zap.Error(err))
	}
}
