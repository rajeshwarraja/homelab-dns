# Stage 1: Build
FROM rust:1.97-alpine AS builder

WORKDIR /build

# Install build dependencies
RUN apk add --no-cache \
    musl-dev \
    pkgconfig

# Copy manifests
COPY Cargo.toml Cargo.lock* ./

# Copy source tree
COPY src ./src

# Build the application
RUN cargo build --release

# Stage 2: Runtime
FROM alpine:3.20

WORKDIR /app

# Install runtime dependencies (ca-certificates for HTTPS)
RUN apk add --no-cache ca-certificates

# Copy binary from builder
COPY --from=builder /build/target/release/homelab-dns /app/homelab-dns

# DNS ports
EXPOSE 53/tcp 53/udp

# Health check (curl to localhost DNS?)
# Not really applicable for DNS, but we can check if the process is running
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ps aux | grep homelab-dns | grep -v grep || exit 1

ENTRYPOINT ["/app/homelab-dns"]
