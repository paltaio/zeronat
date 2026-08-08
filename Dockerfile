FROM alpine:3.24
RUN apk add --no-cache iptables nftables \
    && mkdir -p /run/zeronat \
    && chown 65532:0 /run/zeronat \
    && chmod 0770 /run/zeronat
ARG TARGETPLATFORM
COPY dist/${TARGETPLATFORM}/zeronat /zeronat
ENTRYPOINT ["/zeronat"]
