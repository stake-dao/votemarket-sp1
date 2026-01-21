# Votemarket SP1 Verifier - Justfile
# Run `just --list` to see all available commands

# Default recipe: show help
default:
    @just --list

# ============================================================================
# BUILD COMMANDS
# ============================================================================

# Build the entire workspace in release mode
build:
    cargo build --release

# Build in debug mode (faster compilation, slower execution)
build-debug:
    cargo build

# Build the guest circuit (compiles to RISC-V ELF for ZKVM)
build-guest:
    cd program && cargo prove build

# Clean all build artifacts
clean:
    cargo clean

# ============================================================================
# VKEY (Verification Key)
# ============================================================================

# Get the VKEY (deterministic bytes32 identifying the circuit)
vkey:
    cd script && VKEY_ONLY=true cargo run --release

# ============================================================================
# EXECUTE / MOCK MODE (Development)
# ============================================================================

# Run in mock mode (executes guest logic natively, no ZK proof)
mock:
    cd script && RUN_MODE=mock RUST_LOG=info cargo run --release

# Run in mock mode with debug output
mock-debug:
    cd script && RUN_MODE=mock RUST_LOG=debug cargo run --release

# ============================================================================
# PROVE MODE (Real Proof Generation)
# ============================================================================
# Note: PLONK and Groth16 proofs require the Succinct Prover Network.
# Set NETWORK_PRIVATE_KEY to your requester account's private key.
# Get PROVE tokens at https://network.succinct.xyz/

# Generate a PLONK proof (recommended for production, on-chain verifiable)
# Requires: NETWORK_PRIVATE_KEY
prove:
    cd script && RUN_MODE=prove PROOF_KIND=plonk VERIFY_PROOF=true RUST_LOG=info cargo run --release

# Generate a PLONK proof without verification
# Requires: NETWORK_PRIVATE_KEY
prove-fast:
    cd script && RUN_MODE=prove PROOF_KIND=plonk VERIFY_PROOF=false RUST_LOG=info cargo run --release

# Generate a Groth16 proof (alternative on-chain verifiable format)
# Requires: NETWORK_PRIVATE_KEY
prove-groth16:
    cd script && RUN_MODE=prove PROOF_KIND=groth16 VERIFY_PROOF=true RUST_LOG=info cargo run --release

# Generate a compressed STARK proof (not on-chain verifiable, for testing)
# Can be generated locally without the network - works with any Rust version
# Recommended if you don't have Rust 1.88+ for network proving
prove-compressed:
    cd script && RUN_MODE=prove PROOF_KIND=compressed VERIFY_PROOF=true RUST_LOG=info cargo run --release

# Generate a core STARK proof (development only)
prove-core:
    cd script && RUN_MODE=prove PROOF_KIND=core VERIFY_PROOF=false RUST_LOG=info cargo run --release

# ============================================================================
# RPC MODE (Fetch proofs from Ethereum)
# ============================================================================

# Run in prove mode with RPC source
# Requires: NETWORK_PRIVATE_KEY, ETHEREUM_MAINNET_RPC_URL, GAUGE, ACCOUNT
# Optional: BLOCK_NUMBER (default: latest), EPOCH (default: from block), GAUGE_CONTROLLER (default: protocol), slot env vars (default: protocol defaults)
prove-rpc:
    cd script && PROOF_SOURCE=rpc RUN_MODE=prove PROOF_KIND=plonk VERIFY_PROOF=true RUST_LOG=info cargo run --release

# Run in mock mode with RPC source (test fetching without proof generation)
mock-rpc:
    cd script && PROOF_SOURCE=rpc RUN_MODE=mock RUST_LOG=info cargo run --release

# ============================================================================
# TOOLKIT MODE (External proof toolkit)
# ============================================================================

# Run in prove mode with toolkit source
# Requires: NETWORK_PRIVATE_KEY, ETHEREUM_MAINNET_RPC_URL, and toolkit installed
prove-toolkit:
    cd script && PROOF_SOURCE=toolkit RUN_MODE=prove PROOF_KIND=plonk VERIFY_PROOF=true RUST_LOG=info cargo run --release

# Run in mock mode with toolkit source
mock-toolkit:
    cd script && PROOF_SOURCE=toolkit RUN_MODE=mock RUST_LOG=info cargo run --release

# ============================================================================
# JSON INPUT MODE
# ============================================================================

# Run in prove mode with JSON input file
# Requires: NETWORK_PRIVATE_KEY for PLONK/Groth16 proofs
# Usage: just prove-json ./path/to/input.json
prove-json input_file:
    cd script && INPUT_JSON={{input_file}} RUN_MODE=prove PROOF_KIND=plonk VERIFY_PROOF=true RUST_LOG=info cargo run --release

# Run in mock mode with JSON input file
# Usage: just mock-json ./path/to/input.json
mock-json input_file:
    cd script && INPUT_JSON={{input_file}} RUN_MODE=mock RUST_LOG=info cargo run --release

# ============================================================================
# TESTING
# ============================================================================

# Run all tests
test:
    cargo test

# Run guest circuit tests only
test-guest:
    cd program && cargo test

# Run script tests only
test-script:
    cd script && cargo test

# Run shared library tests only
test-shared:
    cd shared && cargo test

# ============================================================================
# DEVELOPMENT UTILITIES
# ============================================================================

# Check code without building (fast feedback)
check:
    cargo check

# Format all code
fmt:
    cargo fmt

# Check formatting without modifying files
fmt-check:
    cargo fmt -- --check

# Run clippy linter
lint:
    cargo clippy --workspace --all-targets -- -D warnings

# Run clippy with fixes
lint-fix:
    cargo clippy --workspace --all-targets --fix

# ============================================================================
# TOOLKIT SETUP
# ============================================================================

# Setup Python virtual environment and install toolkit
toolkit-setup:
    python3 -m venv .venv
    .venv/bin/pip install --upgrade pip
    .venv/bin/pip install votemarket-toolkit

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
