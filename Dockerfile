FROM public.ecr.aws/docker/library/rust:1-slim-trixie AS builder

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src/ src/

RUN cargo build --release --locked

FROM public.ecr.aws/docker/library/debian:trixie-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/trapbridge /usr/local/bin/trapbridge
COPY REVISIO[N] /

EXPOSE 162/udp
ENTRYPOINT ["trapbridge"]
CMD ["server"]
