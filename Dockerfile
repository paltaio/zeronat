FROM scratch
ARG TARGETPLATFORM
COPY dist/${TARGETPLATFORM}/zeronat /zeronat
ENTRYPOINT ["/zeronat"]
