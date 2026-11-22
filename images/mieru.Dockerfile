# mita (Mieru server) built from the pinned upstream revision; no prebuilt binaries.
FROM golang:1.26.7-alpine AS builder
RUN apk add --no-cache git ca-certificates
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -p 1 -trimpath -ldflags='-s -w' -o /out/mita ./cmd/mita
FROM alpine:3.22
RUN apk add --no-cache ca-certificates tzdata
# mita assigns its RPC socket to this account even when the daemon runs as root.
RUN addgroup -S mita && adduser -S -D -H -G mita mita
COPY --from=builder /out/mita /usr/local/bin/mita
# mita is split into a long-running daemon ("mita run") and a separate control
# client that applies/starts the server config over a local RPC socket. Both
# steps are required for the proxy to actually listen, so the entrypoint starts
# the daemon, waits for its RPC socket, then applies and starts the config.
# The daemon expects its RPC socket directory to exist before it starts.
ENTRYPOINT ["/bin/sh", "-c", "mkdir -p /var/run/mita /etc/mita || exit 1; mita run & pid=$!; trap 'kill $pid 2>/dev/null' TERM INT; i=0; until mita status >/dev/null 2>&1; do kill -0 $pid 2>/dev/null || { wait $pid; exit 1; }; if [ $i -ge 30 ]; then echo 'mita RPC readiness timed out' >&2; kill $pid; wait $pid; exit 1; fi; sleep 1; i=$((i+1)); done; if ! mita replace config /etc/yptun/mita-state.json || ! mita start; then kill $pid; wait $pid; exit 1; fi; wait $pid"]
