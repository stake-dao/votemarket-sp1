# Dockerfile for SP1 Circuit Compilation
# Ensures reproducible VKEY generation matching CI environment

FROM ubuntu:24.04

# Build arguments
ARG SP1_VERSION=v6.3.0

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
    protobuf-compiler \
    python3 \
    python3-pip \
    python3-venv \
    && rm -rf /var/lib/apt/lists/*

# Use existing ubuntu user (UID/GID 1000)
USER ubuntu
WORKDIR /home/ubuntu

# Every ARG below is prefixed PINNED_ because Docker exports build args into the
# environment of every later RUN, where the installers can read them as their own
# options. `ARG SP1UP_COMMIT` is not inert: sp1up takes it as `--commit`, skips the
# prebuilt download, and builds SP1 from a git clone instead (which needs Go and
# fails). Keep our pins out of the `SP1UP_*` and `RUSTUP_*` namespaces.

# Copy rust-toolchain.toml and extract version to install Rust.
# rustup-init comes from the immutable version-pinned archive, not the mutable
# sh.rustup.rs script, and is checked against rustup's published sha256 before
# it runs, so a substituted or truncated download fails this layer loudly
# (dash has no pipefail, so piping curl into a shell reports the shell's
# status, not curl's). Retries are safe, the checksum guards the body. On a rustup
# bump: update both ARGs together, the hash comes from
# https://static.rust-lang.org/rustup/archive/<ver>/x86_64-unknown-linux-gnu/rustup-init.sha256
# (the image is amd64-only, compose forces platform: linux/amd64).
COPY rust-toolchain.toml /tmp/rust-toolchain.toml
ARG PINNED_RUSTUP_VERSION=1.29.0
ARG PINNED_RUSTUP_INIT_SHA256=4acc9acc76d5079515b46346a485974457b5a79893cfb01112423c89aeb5aa10
RUN RUST_VERSION=$(grep 'channel' /tmp/rust-toolchain.toml | sed 's/.*"\(.*\)".*/\1/') && \
    curl --proto '=https' --tlsv1.2 -fsSL --retry 3 --retry-all-errors \
        -o /tmp/rustup-init \
        "https://static.rust-lang.org/rustup/archive/${PINNED_RUSTUP_VERSION}/x86_64-unknown-linux-gnu/rustup-init" && \
    echo "${PINNED_RUSTUP_INIT_SHA256}  /tmp/rustup-init" | sha256sum -c - && \
    chmod +x /tmp/rustup-init && \
    /tmp/rustup-init -y --default-toolchain $RUST_VERSION && \
    rm /tmp/rustup-init
ENV PATH="/home/ubuntu/.cargo/bin:${PATH}"

# Install SP1 toolchain. sp1up is fetched from the commit the v6.3.0 tag
# resolves to (never a moving ref) and checked against a committed hash. This
# replaces the piped sp1.succinct.xyz install wrapper, whose only
# load-bearing steps were this fetch plus a chmod (its shell-profile PATH
# edits are covered by the ENV below). What sp1up itself then downloads (the
# cargo_prove release tarball, and the succinct rust toolchain fetched inside
# cargo-prove) publishes no upstream checksums and stays unverified, see the
# SPEC.md malicious-actor matrix. On an SP1 bump: PINNED_SP1UP_COMMIT from
# `git ls-remote https://github.com/succinctlabs/sp1.git refs/tags/<ver>`,
# PINNED_SP1UP_SHA256 recomputed over the raw sp1up/sp1up file at that commit.
ARG PINNED_SP1UP_COMMIT=ca8700effe99ef7331872cbb4f71f8e29be98c7a
ARG PINNED_SP1UP_SHA256=55d4f6ef8e79e04a7ccd064f75c6a6b44a1694b21cd41aa8e7d0d53eb880a71d
RUN mkdir -p /home/ubuntu/.sp1/bin && \
    curl --proto '=https' --tlsv1.2 -fsSL --retry 3 --retry-all-errors \
        -o /home/ubuntu/.sp1/bin/sp1up \
        "https://raw.githubusercontent.com/succinctlabs/sp1/${PINNED_SP1UP_COMMIT}/sp1up/sp1up" && \
    echo "${PINNED_SP1UP_SHA256}  /home/ubuntu/.sp1/bin/sp1up" | sha256sum -c - && \
    chmod +x /home/ubuntu/.sp1/bin/sp1up
RUN /home/ubuntu/.sp1/bin/sp1up --version ${SP1_VERSION}

# Add SP1 to PATH
ENV PATH="/home/ubuntu/.sp1/bin:${PATH}"

# Install votemarket-toolkit for proof data fetching, from a hash-locked tree.
# The toolkit runs as a subprocess of the prover and is handed the RPC URL, so its
# whole transitive closure is on the proof path: pinning the top-level version
# alone still lets ~60 packages resolve fresh, unverified, on every rebuild.
# --require-hashes makes a substituted or re-published artifact fail the build.
# Regenerate the lock with `just toolkit-lock` (see toolkit-requirements.in).
COPY toolkit-requirements.lock /tmp/toolkit-requirements.lock
RUN python3 -m pip install --user --break-system-packages \
    --require-hashes -r /tmp/toolkit-requirements.lock
ENV PATH="/home/ubuntu/.local/bin:${PATH}"

# Pre-create directories that will be mounted as volumes
# This ensures correct ownership when volumes are first created
RUN mkdir -p /home/ubuntu/.cargo/registry \
    /home/ubuntu/.cargo/git

# Switch back to root for entrypoint (will drop privileges after fixing permissions)
USER root

# Set working directory for mounted code
WORKDIR /workspace

# Copy entrypoint script
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["help"]
