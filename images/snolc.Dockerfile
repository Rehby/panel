# The pinned YPtun source contains these exact static executables with builtin modules.
FROM alpine:3.22
ARG TARGETARCH
COPY snolc/prebuilt/snolc-linux-${TARGETARCH} /usr/local/bin/snolc
RUN chmod 0755 /usr/local/bin/snolc && apk add --no-cache ca-certificates
ENTRYPOINT ["/usr/local/bin/snolc"]
CMD ["run", "/etc/yptun/snolc.toml"]
