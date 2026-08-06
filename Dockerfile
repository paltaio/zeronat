FROM alpine:3.24
RUN apk add --no-cache iptables nftables \
    && mkdir -p /run/zeronat \
    && chown 65532:65532 /run/zeronat \
    && chmod 0700 /run/zeronat
ARG TARGETPLATFORM
COPY dist/${TARGETPLATFORM}/zeronat /zeronat
USER 65532:65532
ENTRYPOINT ["/zeronat"]
