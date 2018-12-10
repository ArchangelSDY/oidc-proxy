FROM alpine

LABEL Name=ArchangelSDY/oidc-proxy \
      Release=https://github.com/ArchangelSDY/oidc-proxy \
      Url=https://github.com/ArchangelSDY/oidc-proxy \
      Help=https://github.com/ArchangelSDY/oidc-proxy/issues

RUN apk add --no-cache ca-certificates

ADD bin/oidc-proxy /opt/oidc-proxy

WORKDIR "/opt"

ENTRYPOINT ["/opt/oidc-proxy"]
