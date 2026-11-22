# mita (Mieru server) built from the pinned upstream revision; no prebuilt binaries.
FROM golang:1.26.7-alpine AS builder
RUN apk add --no-cache git ca-certificates
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -p 1 -trimpath -ldflags='-s -w' -o /out/mita ./cmd/mita
FROM alpine:3.22
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /out/mita /usr/local/bin/mita
# mita is split into a long-running daemon ("mita run") and a separate control
# client that applies/starts the server config over a local RPC socket. Both
# steps are required for the proxy to actually listen, so the entrypoint starts
# the daemon, waits for its RPC socket, then applies and starts the config.
ENTRYPOINT ["/bin/sh", "-c", "mita run & pid=$!; trap 'kill $pid 2>/dev/null' TERM INT; i=0; while [ $i -lt 30 ] && ! mita status >/dev/null 2>&1; do sleep 1; i=$((i+1)); done; mita apply config /etc/yptun/mita-state.json; mita start || true; wait $pid"]
