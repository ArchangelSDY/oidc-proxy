# OIDC-Proxy

A proxy that uses OpenID Connect to drive authentication for other apps.

Currently it's tested with Kubernetes API server.


## Configurations

```
--listen                    <string>     Bind address
--client-id                 <string>     Client ID
--client-secret             <string>     Client Secret
--issuer-url                <string>     OIDC issuer discovery URL
--redirect-url              <string>     OAuth callback redirecion URL
--tls-cert                  <string>     TLS certificate file
--tls-key                   <string>     TLS key file
--session-encryption-key    <string>     An AES key to encrypt session in cookie
--upstream-url              <string>     Upstream URL
--upstream-user-header      <string>     Additional header passing user name to upstream
--upstream-group-header     <string>     Additional header passing group name to upstream
--user-claim                <string>     Claim in the ID token to extract user name
--groups-claim              <string>     Claim in the ID token to extract group names
--secure-cookie                          Set cookie secure flag
```

## Build

```
mkdir -p oidc-proxy/src/github.com/ArchangelSDY
git clone https://github.com/ArchangelSDY/oidc-proxy oidc-proxy/src/github.com/ArchangelSDY/oidc-proxy

cd oidc-proxy
export GOPATH=`pwd`

cd src/github.com/ArchangelSDY/oidc-proxy
dep ensure
go build -o oidc-proxy github.com/ArchangelSDY/oidc-proxy
```

## License

MIT
