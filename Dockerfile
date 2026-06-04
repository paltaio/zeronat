FROM rust:alpine AS build
RUN apk add --no-cache musl-dev && \
    rustup toolchain install nightly --profile minimal --component rust-src
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
ENV RUSTFLAGS="-Zlocation-detail=none -Zfmt-debug=none -Zunstable-options -Cpanic=immediate-abort"
RUN TARGET="$(rustc -vV | sed -n 's/^host: //p')" && \
    cargo +nightly build \
      -Z build-std=std,panic_abort \
      -Z build-std-features=optimize_for_size \
      --target "$TARGET" --release && \
    cp "target/$TARGET/release/zeronat" /zeronat

FROM scratch
COPY --from=build /zeronat /zeronat
ENTRYPOINT ["/zeronat"]
