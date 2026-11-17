FROM golang:1.26.7-alpine AS builder
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -p 1 -trimpath -ldflags='-s -w' -o /out/tgwebproxy ./cmd/tgwebproxy
FROM alpine:3.22
RUN apk add --no-cache ca-certificates && adduser -D -H -u 10001 relay
COPY --from=builder /out/tgwebproxy /usr/local/bin/tgwebproxy
USER relay
ENTRYPOINT ["/usr/local/bin/tgwebproxy"]
CMD ["-config", "/etc/yptun/relay.toml"]
