ARG ALPINE_VERSION=3.22

FROM mcr.microsoft.com/devcontainers/base:alpine-${ALPINE_VERSION} AS dev

# Install system dependencies
RUN apk add --no-cache \
    curl \
    gcc \
    g++ \
    musl-dev \
    openssl-dev \
    openssl-libs-static \
    sqlite-dev \
    pkgconfig \
    git \
    bash

# Switch to vscode user for Rust installation
USER vscode

# Install Rust toolchain for vscode user
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y \
    --default-toolchain stable \
    --profile default \
    && source "$HOME/.cargo/env" \
    && rustup component add rustfmt clippy rust-analyzer

# Add Rust to PATH for vscode user
ENV PATH="/home/vscode/.cargo/bin:${PATH}"

# Install Rust development tools
RUN source "$HOME/.cargo/env" && \
    cargo install sqlx-cli --no-default-features --features sqlite && \
    cargo install cargo-watch

# Switch back to root for remaining system-level operations
USER root

# Install additional tools
RUN apk add --no-cache \
    jq \
    redis

