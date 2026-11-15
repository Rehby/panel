FROM golang:1.26.7-alpine AS builder
RUN apk add --no-cache git ca-certificates
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -p 1 -trimpath -ldflags='-s -w' -o /out/olcrtc ./cmd/olcrtc
FROM alpine:3.22
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /out/olcrtc /usr/local/bin/olcrtc
ENTRYPOINT ["/usr/local/bin/olcrtc"]
CMD ["/etc/yptun/config.conf"]
