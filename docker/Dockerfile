# Dockerfile for SP1 Circuit Compilation
# Ensures reproducible VKEY generation matching CI environment

FROM ubuntu:24.04

# Build arguments
ARG SP1_VERSION=v5.2.4

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    git \
    build-essential \
    pkg-config \
    libssl-dev \
    ca-certificates \
    gosu \
    python3 \
    python3-pip \
    python3-venv \
    && rm -rf /var/lib/apt/lists/*

# Use existing ubuntu user (UID/GID 1000)
USER ubuntu
WORKDIR /home/ubuntu

# Copy rust-toolchain.toml and extract version to install Rust
COPY rust-toolchain.toml /tmp/rust-toolchain.toml
RUN RUST_VERSION=$(grep 'channel' /tmp/rust-toolchain.toml | sed 's/.*"\(.*\)".*/\1/') && \
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain $RUST_VERSION
ENV PATH="/home/ubuntu/.cargo/bin:${PATH}"

# Install SP1 toolchain
RUN curl -L https://sp1.succinct.xyz | bash
RUN /home/ubuntu/.sp1/bin/sp1up --version ${SP1_VERSION}

# Add SP1 to PATH
ENV PATH="/home/ubuntu/.sp1/bin:${PATH}"

# Install votemarket-toolkit for proof data fetching
RUN python3 -m pip install --user --break-system-packages votemarket-toolkit
ENV PATH="/home/ubuntu/.local/bin:${PATH}"

# Pre-create directories that will be mounted as volumes
# This ensures correct ownership when volumes are first created
RUN mkdir -p /home/ubuntu/.cargo/registry \
    /home/ubuntu/.cargo/git \
    /home/ubuntu/.sp1

# Switch back to root for entrypoint (will drop privileges after fixing permissions)
USER root

# Set working directory for mounted code
WORKDIR /workspace

# Copy entrypoint script
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["help"]
