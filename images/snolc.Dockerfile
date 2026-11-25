# The pinned YPtun source contains these exact static executables with builtin modules.
FROM alpine:3.22 AS binary
COPY snolc/prebuilt/snolc-linux-* /prebuilt/
RUN apk_arch=$(apk --print-arch) && \
    case "$apk_arch" in \
        x86_64) arch=amd64 ;; \
        aarch64) arch=arm64 ;; \
        *) echo "snolc: unsupported architecture: $apk_arch" >&2; exit 1 ;; \
    esac && \
    cp "/prebuilt/snolc-linux-$arch" /snolc && chmod 0755 /snolc

FROM alpine:3.22
COPY --from=binary /snolc /usr/local/bin/snolc
RUN apk add --no-cache ca-certificates
ENTRYPOINT ["/usr/local/bin/snolc"]
CMD ["run", "/etc/yptun/snolc.toml"]
