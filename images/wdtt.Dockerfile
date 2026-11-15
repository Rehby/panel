FROM golang:1.26.7-alpine AS builder
RUN apk add --no-cache git
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -p 1 -trimpath -ldflags='-s -w' -o /out/wdtt ./server
FROM alpine:3.22
RUN apk add --no-cache ca-certificates iproute2 iptables
COPY --from=builder /out/wdtt /usr/local/bin/wdtt
ENTRYPOINT ["/usr/local/bin/wdtt"]
