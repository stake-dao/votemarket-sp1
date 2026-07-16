# Votemarket SP1 Verifier - Justfile
# Run `just --list` to see all available commands

# The lock's resolution floor. Sub-3.12 interpreters resolve a different pandas and
# numpy, so a lock that supported them would put the venv and the image on different
# code -- the divergence the lock exists to remove. See toolkit-requirements.in.
TOOLKIT_PYTHON_FLOOR := "3.12"

# Default recipe: show help
default:
    @just --list

# ============================================================================
# MAIN COMMANDS (Docker-based, recommended)
# ============================================================================
# These commands run in Docker for reproducible builds that match CI.
# First build will be slow due to toolchain installation; subsequent builds are cached.

# Build the Docker image for SP1 compilation
build:
    docker compose -f docker/docker-compose.yml build

# Build the guest circuit in Docker
build-guest:
    docker compose -f docker/docker-compose.yml run --rm sp1 build-guest

# Extract VKEY using Docker
vkey:
    docker compose -f docker/docker-compose.yml run --rm sp1 vkey

# Verify VKEY matches .vkey.prod
vkey-verify:
    docker compose -f docker/docker-compose.yml run --rm sp1 vkey-verify

# Clean Docker caches (cargo registry/git, build artifacts)
# The explicit sp1-cache removal is transitional: that volume is no longer
# declared, so `down -v` cannot reach it and it would linger forever on machines
# that predate its removal. Drop this line once the team has cycled past the
# release that dropped the volume (~2 releases).
clean:
    docker compose -f docker/docker-compose.yml down -v
    -docker volume rm -f docker_sp1-cache 2>/dev/null
    @echo "Docker volumes cleaned"

# ============================================================================
# PROOF GENERATION (Docker-based)
# ============================================================================
# All proof commands require an input.json file with proof parameters.
# PLONK and Groth16 proofs also require NETWORK_PRIVATE_KEY env var.
# Get PROVE tokens at https://network.succinct.xyz/

# Run in mock mode (executes guest logic without ZK proof)
# Usage: just mock ./path/to/input.json
mock input_file:
    docker compose -f docker/docker-compose.yml run --rm -e INPUT_JSON=/workspace/{{input_file}} sp1 mock

# Run in mock mode with debug output
# Usage: just mock-debug ./path/to/input.json
mock-debug input_file:
    docker compose -f docker/docker-compose.yml run --rm -e INPUT_JSON=/workspace/{{input_file}} sp1 mock-debug

# Generate a PLONK proof (recommended for production, on-chain verifiable)
# Requires: NETWORK_PRIVATE_KEY env var
# Usage: just prove ./path/to/input.json
prove input_file:
    docker compose -f docker/docker-compose.yml run --rm -e INPUT_JSON=/workspace/{{input_file}} sp1 prove

# Generate a Groth16 proof (alternative on-chain verifiable format)
# Requires: NETWORK_PRIVATE_KEY env var
# Usage: just prove-groth16 ./path/to/input.json
prove-groth16 input_file:
    docker compose -f docker/docker-compose.yml run --rm -e INPUT_JSON=/workspace/{{input_file}} sp1 prove-groth16

# Generate a compressed STARK proof (not on-chain verifiable, for testing)
# Can be generated locally without the prover network
# Usage: just prove-compressed ./path/to/input.json
prove-compressed input_file:
    docker compose -f docker/docker-compose.yml run --rm -e INPUT_JSON=/workspace/{{input_file}} sp1 prove-compressed

# Generate a core STARK proof (development only)
# Usage: just prove-core ./path/to/input.json
prove-core input_file:
    docker compose -f docker/docker-compose.yml run --rm -e INPUT_JSON=/workspace/{{input_file}} sp1 prove-core

# ============================================================================
# TOOLKIT SETUP
# ============================================================================

# Setup Python virtual environment and install the hash-locked toolkit
toolkit-setup:
    python3 -m venv .venv
    # Check the floor before pip does: below it, pip fails deep inside resolution
    # with an error that names a transitive package and never mentions the floor.
    .venv/bin/python -c "import sys; \
      floor = tuple(int(p) for p in '{{TOOLKIT_PYTHON_FLOOR}}'.split('.')); \
      sys.exit(0) if sys.version_info[:2] >= floor else sys.exit( \
        'toolkit-requirements.lock is resolved for Python {{TOOLKIT_PYTHON_FLOOR}}+, ' \
        'this venv is %d.%d. See toolkit-requirements.in.' % sys.version_info[:2])"
    .venv/bin/pip install --upgrade pip
    .venv/bin/pip install --require-hashes -r toolkit-requirements.lock

# Regenerate toolkit-requirements.lock from toolkit-requirements.in (needs `uv`)
# Run after any edit to toolkit-requirements.in, then re-verify against the image.
# -U is not optional: uv reads an existing -o file back as resolution preferences,
# so without it a stale or hand-edited lock survives the very command meant to be
# its correcting authority, and gets silently ratified.
toolkit-lock:
    uv pip compile toolkit-requirements.in --universal --generate-hashes \
      --python-version {{TOOLKIT_PYTHON_FLOOR}} -U -o toolkit-requirements.lock

# Activate toolkit environment hint
toolkit-activate:
    @echo "Run: source .venv/bin/activate"

# ============================================================================
# INFO & DOCUMENTATION
# ============================================================================

# Show environment variable reference
env-help:
    @echo "Environment Variables Reference:"
    @echo "================================="
    @echo ""
    @echo "Run Mode:"
    @echo "  RUN_MODE         - mock | prove (default: mock)"
    @echo "  PROOF_KIND       - core | compressed | plonk | groth16 (default: plonk)"
    @echo "  VERIFY_PROOF     - true | false (default: false)"
    @echo "  VKEY_ONLY        - true | false (default: false)"
    @echo ""
    @echo "Prover Network (required for plonk/groth16):"
    @echo "  NETWORK_PRIVATE_KEY - Ethereum private key for Succinct Prover Network"
    @echo "                        Get PROVE tokens at https://network.succinct.xyz/"
    @echo ""
    @echo "Data Source:"
    @echo "  PROOF_SOURCE     - rpc | toolkit (default: toolkit)"
    @echo "  INPUT_JSON       - Path to JSON input file (overrides env vars)"
    @echo "  RPC_REQUEST_TIMEOUT_SECS - Wall-clock ceiling on one RPC call"
    @echo "                        (default: 30). Raise it for very large slot"
    @echo "                        batches or a slow provider."
    @echo "  TOOLKIT_TIMEOUT_SECS - Wall-clock ceiling on the toolkit subprocess"
    @echo "                        (default: 600). Must be a positive integer;"
    @echo "                        a malformed value is an error, not a fallback."
    @echo ""
    @echo "RPC Endpoints:"
    @echo "  ETHEREUM_MAINNET_RPC_URL  - Ethereum mainnet RPC (required)"
    @echo "  OPTIMISM_MAINNET_RPC_URL  - Optimism RPC"
    @echo "  ARBITRUM_MAINNET_RPC_URL  - Arbitrum RPC"
    @echo "  BASE_MAINNET_RPC_URL      - Base RPC"
    @echo "  POLYGON_MAINNET_RPC_URL   - Polygon RPC"
    @echo "  BSC_MAINNET_RPC_URL       - BSC RPC"
    @echo ""
    @echo "Contract Parameters:"
    @echo "  CHAIN_ID                  - Chain ID (default: 1)"
    @echo "  BLOCK_NUMBER              - Block number, hex or decimal (default: latest)"
    @echo "  EPOCH                     - Override epoch timestamp (default: from block)"
    @echo "  PROTOCOL                  - curve | balancer | frax | fxn | pendle | yb (default: curve)"
    @echo "  GAUGE                     - Gauge address (required)"
    @echo "  ACCOUNT                   - User account address (required)"
    @echo ""
    @echo "Protocol Defaults (optional for known protocols):"
    @echo "  GAUGE_CONTROLLER          - GaugeController address (auto-detected for known protocols)"
    @echo "  WEIGHT_MAPPING_SLOT       - points_weight mapping slot"
    @echo "  LAST_VOTE_MAPPING_SLOT    - last_user_vote mapping slot"
    @echo "  USER_SLOPE_MAPPING_SLOT   - vote_user_slopes mapping slot"
    @echo "  Note: These are auto-detected for curve, balancer, frax, fxn, pendle, yb"
    @echo ""
    @echo "Output:"
    @echo "  PROOF_OUTPUT     - Output proof binary filename (default: proof.bin)"
    @echo "  PROOF_JSON       - Output proof JSON filename (default: proof.json)"

# Show proof kinds explanation
proof-kinds:
    @echo "Proof Kinds:"
    @echo "============"
    @echo ""
    @echo "  core       - Raw SP1 STARK proof (dev only, NOT on-chain verifiable)"
    @echo "  compressed - Recursively compressed STARK (testing, NOT on-chain verifiable)"
    @echo "  plonk      - BN254 PLONK SNARK (PRODUCTION, on-chain verifiable)"
    @echo "  groth16    - BN254 Groth16 SNARK (PRODUCTION, on-chain verifiable)"
    @echo ""
    @echo "For production, always use: just prove (uses plonk)"

# ============================================================================
# DEVELOPER COMMANDS (native, for contributors)
# ============================================================================
# These commands run natively without Docker for faster iteration.
# Warning: Native builds may produce different VKEYs than CI due to
# environment differences. Always use Docker commands for reproducible builds.

# Build the entire workspace in release mode
dev-build:
    cargo build --release

# Build in debug mode (faster compilation, slower execution)
dev-build-debug:
    cargo build

# Build the guest circuit natively (may differ from CI!)
dev-build-guest:
    cd program && cargo prove build

# Clean all build artifacts
dev-clean:
    cargo clean

# Get the VKEY natively (may differ from CI!)
dev-vkey:
    cd script && VKEY_ONLY=true cargo run --release

# Run in mock mode natively
dev-mock:
    cd script && RUN_MODE=mock RUST_LOG=info cargo run --release

# Run in mock mode with debug output natively
dev-mock-debug:
    cd script && RUN_MODE=mock RUST_LOG=debug cargo run --release

# Generate a PLONK proof natively
# Requires: NETWORK_PRIVATE_KEY
dev-prove:
    cd script && RUN_MODE=prove PROOF_KIND=plonk VERIFY_PROOF=true RUST_LOG=info cargo run --release

# Generate a PLONK proof without verification natively
# Requires: NETWORK_PRIVATE_KEY
dev-prove-fast:
    cd script && RUN_MODE=prove PROOF_KIND=plonk VERIFY_PROOF=false RUST_LOG=info cargo run --release

# Generate a Groth16 proof natively
# Requires: NETWORK_PRIVATE_KEY
dev-prove-groth16:
    cd script && RUN_MODE=prove PROOF_KIND=groth16 VERIFY_PROOF=true RUST_LOG=info cargo run --release

# Generate a compressed STARK proof natively
dev-prove-compressed:
    cd script && RUN_MODE=prove PROOF_KIND=compressed VERIFY_PROOF=true RUST_LOG=info cargo run --release

# Generate a core STARK proof natively
dev-prove-core:
    cd script && RUN_MODE=prove PROOF_KIND=core VERIFY_PROOF=false RUST_LOG=info cargo run --release

# Run in mock mode with RPC source natively
dev-mock-rpc:
    cd script && PROOF_SOURCE=rpc RUN_MODE=mock RUST_LOG=info cargo run --release

# Run in prove mode with RPC source natively
dev-prove-rpc:
    cd script && PROOF_SOURCE=rpc RUN_MODE=prove PROOF_KIND=plonk VERIFY_PROOF=true RUST_LOG=info cargo run --release

# Run in mock mode with JSON input file natively
# Usage: just dev-mock-json ./path/to/input.json
dev-mock-json input_file:
    cd script && INPUT_JSON={{input_file}} RUN_MODE=mock RUST_LOG=info cargo run --release

# Run in prove mode with JSON input file natively
# Usage: just dev-prove-json ./path/to/input.json
dev-prove-json input_file:
    cd script && INPUT_JSON={{input_file}} RUN_MODE=prove PROOF_KIND=plonk VERIFY_PROOF=true RUST_LOG=info cargo run --release

# Run in prove mode with toolkit source natively
dev-prove-toolkit:
    cd script && PROOF_SOURCE=toolkit RUN_MODE=prove PROOF_KIND=plonk VERIFY_PROOF=true RUST_LOG=info cargo run --release

# Run in mock mode with toolkit source natively
dev-mock-toolkit:
    cd script && PROOF_SOURCE=toolkit RUN_MODE=mock RUST_LOG=info cargo run --release

# Run all tests
dev-test:
    cargo test

# Run guest circuit tests only
dev-test-guest:
    cd program && cargo test

# Run script tests only
dev-test-script:
    cd script && cargo test

# Run shared library tests only
dev-test-shared:
    cd shared && cargo test

# Check code without building (fast feedback)
dev-check:
    cargo check

# Format all code
dev-fmt:
    cargo fmt

# Check formatting without modifying files
dev-fmt-check:
    cargo fmt -- --check

# Run clippy linter
dev-lint:
    cargo clippy --workspace --all-targets -- -D warnings

# Run clippy with fixes
dev-lint-fix:
    cargo clippy --workspace --all-targets --fix

# Interactive shell in container for debugging
dev-shell:
    docker compose -f docker/docker-compose.yml run --rm sp1 shell