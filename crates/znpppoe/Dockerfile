FROM rust:1-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY . .
ENV RUSTFLAGS="-C strip=symbols"
RUN cargo build --release -p znpppoe

FROM scratch
COPY --from=build /src/target/release/znpppoe /znpppoe
ENTRYPOINT ["/znpppoe"]
