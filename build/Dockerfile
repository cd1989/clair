FROM golang:1.10-alpine as base
ADD .   /go/src/github.com/coreos/clair/
WORKDIR /go/src/github.com/coreos/clair/
RUN apk add --no-cache git rpm xz
RUN export CLAIR_VERSION=$(git describe --always --tags --dirty) \
    && go install -ldflags "-X github.com/coreos/clair/pkg/version.Version=$CLAIR_VERSION" -v github.com/coreos/clair/cmd/clair

FROM alpine:3.8
LABEL maintainer="chende@caicloud.io"
RUN apk add --no-cache git rpm xz
COPY --from=base /go/bin/clair /clair
COPY build/dumb-init /dumb-init
VOLUME /config
EXPOSE 6060 6061
RUN chmod +x /clair \
    && chmod +x /dumb-init
HEALTHCHECK --interval=30s --timeout=10s --retries=3 CMD wget -qO- 127.0.0.1:6061/health || exit 1
ENTRYPOINT ["/dumb-init", "--"]
CMD ["/clair", "-config", "/config/config.yaml"]

