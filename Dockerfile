# syntax=docker/dockerfile:1

ARG ALPINE_VERSION=3.22

# ============================================
# Builder Stage
# ============================================
FROM alpine:${ALPINE_VERSION} AS builder

# Install build dependencies
RUN apk add --no-cache \
    curl \
    gcc \
    g++ \
    musl-dev \
    openssl-dev \
    openssl-libs-static \
    sqlite-dev \
    pkgconfig \
    git

# Install Rust toolchain
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y \
    --default-toolchain stable \
    --profile minimal \
    --no-modify-path

ENV PATH="/root/.cargo/bin:${PATH}"

# Create app directory
WORKDIR /app

# Copy dependency manifests
COPY Cargo.toml Cargo.lock ./

# Create dummy main to cache dependencies
RUN mkdir src && \
    echo "fn main() {}" > src/main.rs && \
    echo "" > src/lib.rs && \
    cargo build --release && \
    rm -rf src target/release/deps/guardix*

# Copy source code and SQLx dependencies
COPY src ./src
COPY migrations ./migrations
COPY .sqlx ./.sqlx

# Build the actual application
RUN cargo build --release --locked

# ============================================
# Runtime Stage
# ============================================
FROM alpine:${ALPINE_VERSION}

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    openssl \
    sqlite-libs \
    libgcc

# Create non-root user
RUN addgroup -g 1000 guardix && \
    adduser -D -u 1000 -G guardix guardix

# Create app directories
RUN mkdir -p /app/data /app/config && \
    chown -R guardix:guardix /app

WORKDIR /app

# Copy binary from builder
COPY --from=builder --chown=guardix:guardix /app/target/release/guardix /usr/local/bin/guardix

# Copy default configuration
COPY --chown=guardix:guardix config.yaml.example /app/config.yaml

# Switch to non-root user
USER guardix

# Expose default port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:5000/health || exit 1

# Default command
CMD ["guardix"]

