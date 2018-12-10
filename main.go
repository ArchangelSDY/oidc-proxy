package main

import (
	flags "github.com/jessevdk/go-flags"
	"go.uber.org/zap"
)

type Options struct {
	Listen               string   `long:"listen"`
	ClientId             string   `long:"client-id"`
	ClientSecret         string   `long:"client-secret"`
	IssuerURL            string   `long:"issuer-url"`
	RedirectURL          string   `long:"redirect-url"`
	TLSCertFile          string   `long:"tls-cert"`
	TLSKeyFile           string   `long:"tls-key"`
	SessionEncryptionKey string   `long:"session-encryption-key"`
	UpstreamURL          string   `long:"upstream-url"`
	UpstreamUserHeader   []string `long:"upstream-user-header"`
	UpstreamGroupHeader  []string `long:"upstream-group-header"`
	UserPrefix           string   `long:"user-prefix"`
	UserClaim            string   `long:"user-claim"`
	GroupsPrefix         string   `long:"groups-prefix"`
	GroupsClaim          string   `long:"groups-claim"`
}

func (opts *Options) Parse() error {
	if _, err := flags.Parse(opts); err != nil {
		return err
	}

	return nil
}

func main() {
	logger, err := zap.NewDevelopment()
	if err != nil {
		panic(err)
	}
	defer logger.Sync()

	opts := &Options{}
	if err = opts.Parse(); err != nil {
		if flagsErr, ok := err.(*flags.Error); ok && flagsErr.Type == flags.ErrHelp {
			return
		} else {
			logger.Fatal("Fail to parse flags", zap.Error(err))
		}
	}

	if opts.SessionEncryptionKey == "" {
		logger.Warn("Session is not encrypted. Should only use this in dev environment.")
	}

	logger.Info("Listening...")

	server, err := NewServer(opts, logger)
	if err != nil {
		logger.Fatal("Fail to initialize server", zap.Error(err))
	}

	if err = server.Listen(opts.Listen); err != nil {
		logger.Fatal("Fail to serve", zap.Error(err))
	}
}
