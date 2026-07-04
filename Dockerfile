FROM alpine:3.24
RUN apk add --no-cache iptables nftables
ARG TARGETPLATFORM
COPY dist/${TARGETPLATFORM}/zeronat /zeronat
ENTRYPOINT ["/zeronat"]
