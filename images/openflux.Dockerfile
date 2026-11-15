FROM golang:1.26.7-alpine AS builder
RUN apk add --no-cache git ca-certificates
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -p 1 -trimpath -ldflags='-s -w' -o /out/openflux .
FROM alpine:3.22
RUN apk add --no-cache ca-certificates
COPY --from=builder /out/openflux /usr/local/bin/openflux
ENTRYPOINT ["/usr/local/bin/openflux"]
