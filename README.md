# Votemarket SP1 Verifier

A Zero-Knowledge proof system for the Votemarket protocol, replacing expensive on-chain Merkle-Patricia Trie (MPT) verification with constant-size ZK proofs.

## Table of Contents

- [Introduction](#introduction)
  - [What is Zero-Knowledge (ZK)?](#what-is-zero-knowledge-zk)
  - [Why ZK for Votemarket?](#why-zk-for-votemarket)
- [Problem Statement](#problem-statement)
- [Solution: ZK Compression](#solution-zk-compression)
- [Architecture](#architecture)
  - [Repository Structure](#repository-structure)
  - [System Components](#system-components)
  - [Data Flow](#data-flow)
- [Design Decisions](#design-decisions)
- [Integration with Other Repositories](#integration-with-other-repositories)
- [Getting Started](#getting-started)
- [Quick Commands with Just](#quick-commands-with-just)
- [Usage](#usage)
- [Proof Modes](#proof-modes)
- [Configuration](#configuration)
- [Testing](#testing)
- [Future Evolution](#future-evolution)

## Introduction

### What is Zero-Knowledge (ZK)?

**Zero-Knowledge proofs** are a cryptographic technique that allows one party (the "prover") to prove to another party (the "verifier") that a statement is true, **without revealing any information beyond the validity of the statement itself**.

In our context:

- **Statement**: "These storage values exist in Ethereum's state at block X"
- **Proof**: A tiny cryptographic proof (~300 bytes) that this statement is true
- **Benefit**: The verifier (smart contract) can trust the values without seeing the full proof data

**Analogy**: Imagine proving you're over 18 without showing your ID. A ZK proof lets you prove the fact without revealing your birthdate, name, or any other information.

### Why ZK for Votemarket?

Votemarket is a **cross-chain incentive protocol** that distributes rewards based on voting data from Ethereum mainnet (e.g., Curve gauge weights, user votes). This data must be **cryptographically verified** on L2 chains (Arbitrum, Optimism, etc.) before rewards can be claimed.

**The challenge**: Ethereum's state is stored in a Merkle-Patricia Trie (MPT). To prove a storage value, you need to submit the entire path from the state root to the value (typically **2-3KB of calldata per proof**).

**The solution**: Use ZK proofs to verify MPT proofs off-chain, then submit a single ~300 byte proof on-chain that attests to hundreds of verified values.

## Problem Statement

### The Calldata Bottleneck

The current Votemarket implementation uses **on-chain MPT verification**:

```
┌─────────────────────────────────────────────────────────────────────┐
│                     CURRENT APPROACH (MPT)                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│   User wants to claim rewards for 10 gauges + their vote data       │
│                                                                     │
│   Each proof requires:                                              │
│   ├── Account proof: ~1-2KB (path to GaugeController account)       │
│   └── Storage proof: ~1KB (path to specific storage slot)           │
│                                                                     │
│   Total for 10 claims: ~20-30KB calldata                            │
│                                                                     │
│   Problems:                                                         │
│   ├── High gas costs (calldata is expensive)                        │
│   ├── Transaction size limits (~128KB max)                          │
│   ├── Block gas limit constraints                                   │
│   └── Poor UX (users must split claims across multiple txs)         │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Real-World Impact

| Scenario          | MPT Approach    | Limitation              |
| ----------------- | --------------- | ----------------------- |
| Single claim      | ~3KB calldata   | Expensive but works     |
| 10 claims batched | ~30KB calldata  | Very expensive          |
| 50 claims batched | ~150KB calldata | Exceeds tx size limit   |
| 100+ claims       | Impossible      | Cannot fit in single tx |

**Bottom line**: The current system caps scalability and increases costs for users and the protocol.

## Solution: ZK Compression

### How It Works

```
┌─────────────────────────────────────────────────────────────────────┐
│                      NEW APPROACH (ZK)                              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│   OFF-CHAIN (this repository)                                       │
│   ┌─────────────────────────────────────────────────────────┐       │
│   │  1. Collect MPT proofs from Ethereum RPC                │       │
│   │  2. Feed proofs to SP1 ZKVM                             │       │
│   │  3. ZKVM verifies all proofs cryptographically          │       │
│   │  4. ZKVM outputs: verified values + ZK proof            │       │
│   └─────────────────────────────────────────────────────────┘       │
│                              │                                      │
│                              ▼                                      │
│   ON-CHAIN (contracts-monorepo)                                     │
│   ┌─────────────────────────────────────────────────────────┐       │
│   │  1. Receive: ZK proof (~300B) + public values (~1KB)    │       │
│   │  2. Verify ZK proof (constant gas: ~300k)               │       │
│   │  3. Trust the verified values                           │       │
│   │  4. Insert into Oracle for claims                       │       │
│   └─────────────────────────────────────────────────────────┘       │
│                                                                     │
│   Result: 100+ claims verified in ONE transaction                   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Benefits Summary

| Metric                | MPT (Before) | ZK (After)      | Improvement      |
| --------------------- | ------------ | --------------- | ---------------- |
| Calldata per claim    | ~3KB         | ~10 bytes       | **300x smaller** |
| Max claims per tx     | ~40          | **Unlimited\*** | **Unbounded**    |
| Gas cost (100 claims) | ~5M gas      | ~400k gas       | **12x cheaper**  |
| User experience       | Multiple txs | Single tx       | **Much better**  |

\*Practically limited by public values encoding, but can handle 500+ claims easily.

## Architecture

### Repository Structure

```
votemarket-sp1/
├── program/              # Guest circuit (runs inside ZKVM)
│   ├── src/
│   │   └── main.rs       # MPT verification logic
│   └── Cargo.toml
│
├── script/               # Host application (runs on server)
│   ├── src/
│   │   └── main.rs       # Proof orchestration
│   └── Cargo.toml
│
├── shared/               # Shared types between guest and host
│   ├── src/
│   │   └── lib.rs        # Input/Output structs
│   └── Cargo.toml
│
├── output/               # Generated proof artifacts
├── justfile              # Command runner recipes
└── README.md
```

### System Components

#### 1. Guest Circuit (`program/`)

The **guest** is the code that runs inside the SP1 Zero-Knowledge Virtual Machine (ZKVM). It:

- Receives inputs (state root, MPT proofs)
- Verifies each MPT proof cryptographically
- Extracts the storage values
- Commits the verified values as "public outputs"

**Think of it as**: The same verification logic that runs on-chain today, but executed in a provable environment.

```rust
// Simplified guest logic
fn main() {
    let input = sp1_zkvm::io::read::<Input>();

    // Verify gauge point data (total votes per gauge)
    let point_results = verify_point_proofs(&input);

    // Verify account data (user votes)
    let account_results = verify_account_proofs(&input);

    // Commit verified data as public output
    sp1_zkvm::io::commit(&Output {
        state_root: input.state_root,
        epoch: input.epoch,
        point_results,
        account_results,
    });
}
```

#### 2. Host Application (`script/`)

The **host** is the orchestration layer that:

- Fetches MPT proofs from Ethereum RPC (or the proof toolkit)
- Prepares inputs for the guest
- Runs the guest in the ZKVM
- Generates the ZK proof
- Saves proof artifacts for on-chain submission

**Think of it as**: The "driver" that feeds data to the circuit and collects the output.

#### 3. Shared Types (`shared/`)

Defines the data structures used by both guest and host:

```rust
// Input to the circuit
pub struct Input {
    pub state_root: B256,           // Ethereum state root
    pub epoch: u64,                 // Week-aligned timestamp
    pub point_requests: Vec<PointRequest>,    // Gauge data requests
    pub account_requests: Vec<AccountRequest>, // User vote requests
}

// Output from the circuit (becomes public values)
pub struct Output {
    pub state_root: B256,
    pub epoch: u64,
    pub point_results: Vec<PointResult>,      // Verified gauge data
    pub account_results: Vec<AccountResult>,  // Verified user votes
}
```

### Data Flow

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                            END-TO-END FLOW                                   │
└──────────────────────────────────────────────────────────────────────────────┘

    ┌─────────────┐         ┌─────────────┐         ┌─────────────┐
    │  Ethereum   │         │   Toolkit   │         │    Host     │
    │    RPC      │◄───────►│  (Python)   │◄───────►│   (Rust)    │
    └─────────────┘         └─────────────┘         └──────┬──────┘
                                                           │
                            ┌──────────────────────────────┘
                            │
                            ▼
                    ┌───────────────┐
                    │    SP1 ZKVM   │
                    │    (Guest)    │
                    │               │
                    │  ┌─────────┐  │
                    │  │ Verify  │  │
                    │  │  MPT    │  │
                    │  │ Proofs  │  │
                    │  └────┬────┘  │
                    │       │       │
                    │       ▼       │
                    │  ┌─────────┐  │
                    │  │ Commit  │  │
                    │  │ Output  │  │
                    │  └─────────┘  │
                    └───────┬───────┘
                            │
                            ▼
                    ┌───────────────┐
                    │  ZK Proof +   │
                    │ Public Values │
                    └───────┬───────┘
                            │
                            ▼
    ┌───────────────────────────────────────────────────────────────┐
    │                      ON-CHAIN (L2)                            │
    │  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐        │
    │  │ ZKVerifier  │───►│   Oracle    │───►│ Votemarket  │        │
    │  │  (verify)   │    │  (store)    │    │  (claims)   │        │
    │  └─────────────┘    └─────────────┘    └─────────────┘        │
    └───────────────────────────────────────────────────────────────┘
```

## Design Decisions

### Public Values (Circuit Output)

The ZK circuit commits **public values** (data that becomes visible on-chain after proof verification). These values are ABI-encoded and passed to `ZKVerifier.verifyAndInsert()`:

```solidity
struct ZKOutput {
    bytes32 stateRoot;              // Ethereum state root verified against
    uint256 epoch;                  // Week-aligned timestamp
    PointResult[] pointResults;     // Verified gauge weight data
    AccountResult[] accountResults; // Verified user vote data
}

struct PointResult {
    address gauge;     // Gauge address
    uint256 epoch;     // Epoch for this data point
    uint256 bias;      // Total votes (points_weight[gauge][epoch].bias)
}

struct AccountResult {
    address account;   // Voter address
    address gauge;     // Gauge voted for
    uint256 slope;     // Vote decay rate
    uint256 end;       // When vote expires
    uint256 lastVote;  // Last vote timestamp (0 for Pendle)
}
```

The `proof_bytes` and `public_values` from the proof artifacts are what get submitted on-chain.

### Trust Model

The ZK circuit receives a `state_root` as input and trusts it implicitly. It does not validate the state root against a block hash inside the circuit. Instead, **validation happens on-chain**: the `ZKVerifier` contract checks that the proof's `state_root` matches the one stored in the Oracle for the given epoch.

This design reuses the existing trust infrastructure. The Oracle already stores validated block headers (including state roots) per epoch, populated by the L1→L2 bridge or authorized providers. By validating against the Oracle, the ZK path maintains the same security guarantees as the MPT path.

```
┌─────────────────────────────────────────────────────────────────────┐
│                         TRUST FLOW                                  │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│   L1 Block Header ──► Oracle.insertBlockNumber() ──► Stored         │
│                                                       stateRoot     │
│                                                          │          │
│   ZK Proof ──► ZKVerifier.verifyAndInsert() ──► Compare against     │
│                                                 stored stateRoot    │
│                                                          │          │
│                                              Match? ──► Insert      │
│                                              Mismatch? ──► Revert   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Semantic Output Format

Rather than outputting raw storage slots (`address, slot, value`), the circuit outputs **semantic structs** that directly map to the Oracle's data model:

- **PointResult**: Contains `gauge`, `epoch`, and `bias` (total votes for a gauge)
- **AccountResult**: Contains `account`, `gauge`, `slope`, `end`, and `lastVote` (user's vote data)

This approach has several benefits:

1. **Readability**: The output is self-documenting. You can understand what each field means without knowing Ethereum storage layouts
2. **On-chain efficiency**: The Solidity decoder directly unpacks into Oracle-compatible structs
3. **Type safety**: Fields have explicit types rather than being raw `uint256` values
4. **Protocol awareness**: The circuit handles protocol-specific differences (e.g., Pendle lacks `lastVote`)

### Parallel Verification Paths

The ZKVerifier **complements** rather than replaces the existing MPT verifier. Both paths coexist:

```
                    ┌─────────────────┐
                    │   User/Bundler  │
                    └────────┬────────┘
                             │
              ┌──────────────┴──────────────┐
              │                             │
              ▼                             ▼
    ┌─────────────────┐           ┌─────────────────┐
    │   MPT Verifier  │           │   ZK Verifier   │
    │   (existing)    │           │     (new)       │
    └────────┬────────┘           └────────┬────────┘
             │                             │
             └──────────────┬──────────────┘
                            │
                            ▼
                    ┌───────────────┐
                    │    Oracle     │
                    │  (shared)     │
                    └───────────────┘
```

This design enables:

- **Gradual migration**: Start with ZK for high-volume batches, keep MPT for edge cases
- **Fallback option**: If ZK proving fails or is unavailable, MPT remains operational
- **A/B testing**: Compare gas costs and reliability before full migration
- **User choice**: Bundlers can optimize based on batch size and urgency

### Single-Epoch Batching

Each ZK proof covers data from **one epoch only**. The epoch is explicitly included in both the circuit input and output:

```rust
// Input
pub struct Input {
    pub state_root: B256,
    pub epoch: u64,  // ◄── Explicit epoch
    pub point_requests: Vec<PointRequest>,
    pub account_requests: Vec<AccountRequest>,
}

// Output
pub struct Output {
    pub state_root: B256,
    pub epoch: u64,  // ◄── Echoed in output
    pub point_results: Vec<PointResult>,
    pub account_results: Vec<AccountResult>,
}
```

Including the epoch explicitly provides:

1. **Replay protection**: A proof for epoch N cannot be replayed for epoch M
2. **Self-contained verification**: The verifier knows exactly which epoch's data is being proven
3. **Simpler implementation**: No need to handle cross-epoch edge cases
4. **Clear trust boundaries**: Each proof is bound to a specific block/state

Multi-epoch batching (proving data across multiple epochs in one proof) is a potential future enhancement using recursive proof composition.

### Prover Infrastructure

Proof generation uses **Succinct's Prover network**: a hosted proving service that handles the computationally intensive ZK proof generation:

```
┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
│   Host Script   │ ──►  │  Prover Network │ ──►  │   ZK Proof      │
│  (prepares      │      │  (generates     │      │  (submit to     │
│   inputs)       │      │   proof)        │      │   chain)        │
└─────────────────┘      └─────────────────┘      └─────────────────┘
```

Benefits of using the Prover Network:

- **No infrastructure overhead**: No need to maintain GPU clusters or specialized hardware
- **Scalability**: The Prover network handles proof generation spikes automatically
- **Reliability**: Managed service with uptime guarantees
- **Cost efficiency**: Pay-per-proof model vs. fixed infrastructure costs

The architecture supports switching to self-hosted proving later if latency or cost requirements change.

## Integration with Other Repositories

This repository is part of a larger system:

```
┌────────────────────────────────────────────────────────────────────┐
│                        VOTEMARKET ECOSYSTEM                        │
├────────────────────────────────────────────────────────────────────┤
│                                                                    │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │               contracts-monorepo                            │   │
│  │  ┌──────────────────────────────────────────────────────┐   │   │
│  │  │  packages/votemarket/                                │   │   │
│  │  │  ├── src/oracle/Oracle.sol       (stores verified    │   │   │
│  │  │  │                                data per epoch)    │   │   │
│  │  │  ├── src/verifiers/Verifier.sol  (MPT verification)  │   │   │
│  │  │  ├── src/verifiers/ZKVerifier.sol (ZK verification)  │◄──┼───┼──────
│  │  │  └── src/Votemarket.sol          (claims/rewards)    │   │   │
│  │  └──────────────────────────────────────────────────────┘   │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              ▲                                     │
│                              │ proofs                              │
│                              │                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │               votemarket-sp1 (this repo)                    │   │
│  │  ├── program/    (ZK circuit - verifies MPT proofs)         │   │
│  │  ├── script/     (host - orchestrates proof generation)     │   │
│  │  └── shared/     (types shared between guest/host)          │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              ▲                                     │
│                              │ MPT proofs                          │
│                              │                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │               votemarket-proof-toolkit                      │   │
│  │  (Python library that fetches proofs from Ethereum RPC)     │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                    │
└────────────────────────────────────────────────────────────────────┘
```

### contracts-monorepo

[`Github repository`](https://github.com/stake-dao/contracts-monorepo/tree/main/packages/votemarket)

Key contracts:

- **Oracle.sol**: Stores verified voting data per epoch
- **Verifier.sol**: Existing MPT verification (will coexist with ZK)
- **ZKVerifier.sol**: New ZK verification contract
- **Votemarket.sol**: Handles campaign creation and reward claims

The **ZKVerifier** contract:

1. Verifies SP1 proofs using Succinct's deployed verifier
2. Decodes public values from the proof
3. Validates state_root against Oracle's epoch block
4. Inserts verified data into Oracle

### votemarket-proof-toolkit

[`Github repository`](https://github.com/stake-dao/votemarket-proof-toolkit)

A Python library that:

- Connects to Ethereum RPC
- Fetches storage proofs (eth_getProof)
- Computes correct storage slots for different protocols
- Formats proofs for the ZK circuit

## Getting Started

### Prerequisites

1. **Rust** (latest stable)
2. **SP1 Toolchain**

```bash
# Install SP1
curl -L https://sp1.succinct.xyz | bash
sp1up
```

### Installation

```bash
git clone https://github.com/stake-dao/votemarket-sp1
cd votemarket-sp1

# Using just (recommended)
just build

# Or manually
cargo build --release
```

### Build the Guest Circuit

```bash
# Using just (recommended)
just build-guest

# Or manually
cd program
cargo prove build
cd ..
```

This compiles the Rust guest code into a RISC-V ELF binary that SP1 can execute.

## Quick Commands with Just

This project uses [just](https://github.com/casey/just) as a command runner to simplify common operations. Install it with:

```bash
# macOS
brew install just

# Linux
cargo install just

# Or see https://github.com/casey/just#installation
```

### Available Commands

Run `just` or `just --list` to see all available commands:

```
Available recipes:
    default           # Show help
    build             # Build the entire workspace in release mode
    build-debug       # Build in debug mode
    build-guest       # Build the guest circuit (RISC-V ELF)
    clean             # Clean all build artifacts
    vkey              # Get the VKEY (verification key)
    mock              # Run in mock mode (no ZK proof)
    mock-debug        # Run in mock mode with debug output
    prove             # Generate a PLONK proof (production)
    prove-fast        # Generate a PLONK proof without verification
    prove-groth16     # Generate a Groth16 proof
    prove-compressed  # Generate a compressed STARK proof
    prove-core        # Generate a core STARK proof
    prove-rpc         # Run in prove mode with RPC source
    mock-rpc          # Run in mock mode with RPC source
    prove-toolkit     # Run in prove mode with toolkit source
    mock-toolkit      # Run in mock mode with toolkit source
    prove-json        # Run in prove mode with JSON input file
    mock-json         # Run in mock mode with JSON input file
    test              # Run all tests
    test-guest        # Run guest circuit tests only
    test-script       # Run script tests only
    test-shared       # Run shared library tests only
    check             # Check code without building
    fmt               # Format all code
    fmt-check         # Check formatting
    lint              # Run clippy linter
    lint-fix          # Run clippy with fixes
    toolkit-setup     # Setup Python venv and install toolkit
    toolkit-activate  # Show activation hint
    env-help          # Show environment variable reference
    proof-kinds       # Show proof kinds explanation
```

### Common Workflows

```bash
# Development cycle
just build-guest    # Build the circuit
just vkey           # Get verification key for contract deployment
just mock           # Test without generating a real proof

# Production proof generation
just prove          # Generate PLONK proof (recommended)
just prove-groth16  # Alternative: Groth16 proof

# With external data sources
ETHEREUM_MAINNET_RPC_URL=https://... just prove-rpc
just prove-json ./input.json

# Testing
just test           # Run all tests
just lint           # Check code quality

# Help
just env-help       # Show all environment variables
just proof-kinds    # Explain proof formats
```

### Extract the Program VKEY

The **Program Verification Key (VKEY)** is a `bytes32` value that uniquely identifies your compiled circuit. It's required when deploying the `ZKVerifier` contract on-chain.

```bash
# Using just (recommended)
just vkey

# Or manually
cd script
VKEY_ONLY=true cargo run --release
```

Output:
```
Program VKEY: 0x0092a652ae3e8ecc3856d301b6d474f25a6bb36d0a4c23880261d3ae26608c6b
```

**Key points about the VKEY:**

- **Deterministic**: The VKEY is derived from the compiled ELF binary. Running this command multiple times produces the same value
- **Circuit identity**: The VKEY acts as a fingerprint for your circuit. The on-chain verifier uses it to ensure proofs were generated by the expected program
- **Rebuild = new VKEY**: If you modify the guest code (`program/src/main.rs`) and rebuild, you'll get a different VKEY and must redeploy the `ZKVerifier` contract
- **Deployment parameter**: Pass this value as the `_programVKey` constructor argument when deploying `ZKVerifier.sol`

The VKEY is also included in `output/proof.json` when generating proofs, under the `program_vkey` field.

## Usage

### Quick Start (Mock Mode)

```bash
# Using just (recommended)
just mock

# Or manually
cd script
RUST_LOG=info cargo run --release
```

Mock mode executes the guest logic natively (no ZK proof generated). Use this for development and testing.

### Generate a Real Proof

```bash
# Using just (recommended)
just prove

# Or manually
cd script
RUN_MODE=prove PROOF_KIND=plonk VERIFY_PROOF=true RUST_LOG=info cargo run --release
```

### Using the Proof Toolkit

```bash
# Setup toolkit (one-time)
just toolkit-setup
source .venv/bin/activate

# Run with toolkit as proof source
ETHEREUM_MAINNET_RPC_URL=https://... just prove-toolkit

# Or manually
cd script
PROOF_SOURCE=toolkit \
ETHEREUM_MAINNET_RPC_URL=https://... \
RUN_MODE=prove \
PROOF_KIND=plonk \
RUST_LOG=info cargo run --release
```

## Proof Modes

SP1 supports multiple proof formats with different trade-offs:

| Mode         | Description      | On-chain Verifiable | Use Case                  |
| ------------ | ---------------- | ------------------- | ------------------------- |
| `core`       | Raw SP1 proof    | No                  | Development only          |
| `compressed` | Compressed proof | No                  | Testing                   |
| `plonk`      | PLONK proof      | **Yes**             | **Production**            |
| `groth16`    | Groth16 proof    | **Yes**             | Production (incoming alt) |

**For actual production, use `PROOF_KIND=plonk`** - this generates proofs that can be verified by on-chain contracts.

### Output Artifacts

After running in proof mode, artifacts are saved to `script/output/`:

- `proof.bin`: Binary-serialized proof bundle
- `proof.json`: Human-readable proof data

```json
{
  "proof_kind": "plonk",
  "proof_bytes": "0x...",
  "public_values_raw": "0x...",
  "public_values_hash": "0x...",
  "output": {
    "state_root": "0x...",
    "epoch": 1700000000,
    "point_results": [...],
    "account_results": [...]
  }
}
```

## Configuration

### Environment Variables

| Variable                   | Description                              | Default |
| -------------------------- | ---------------------------------------- | ------- |
| `RUN_MODE`                 | `mock` or `prove`                        | `mock`  |
| `PROOF_KIND`               | `core`, `compressed`, `plonk`, `groth16` | `plonk` |
| `VERIFY_PROOF`             | Verify proof locally after generation    | `false` |
| `PROOF_SOURCE`             | `rpc` or `toolkit`                       | `rpc`   |
| `INPUT_JSON`               | Path to input JSON file                  | -       |
| `ETHEREUM_MAINNET_RPC_URL` | Ethereum RPC endpoint                    | -       |
| `CHAIN_ID`                 | Chain ID for RPC calls                   | `1`     |
| `BLOCK_NUMBER`             | Block number for proofs                  | Latest  |
| `PROTOCOL`                 | `curve`, `yb`, `pendle`                  | `curve` |

### Input JSON Format

```json
{
  "chain_id": 1,
  "block_number": 23438749,
  "epoch": 1758758400,
  "protocol": "curve",
  "gauge_controller": "0x2F50D538606Fa9EDD2B11E2446BEb18C9D5846bB",
  "slots": {
    "weight_mapping_slot": "0x...",
    "last_vote_mapping_slot": "0x...",
    "user_slope_mapping_slot": "0x..."
  },
  "requests": [
    {
      "type": "point_data",
      "gauge": "0x..."
    },
    {
      "type": "account_data",
      "account": "0x...",
      "gauge": "0x..."
    }
  ]
}
```

## Testing

### Guest Circuit Tests

```bash
# Using just (recommended)
just test-guest

# Or manually
cd program
cargo test
```

### Full Integration Test

```bash
# Using just (recommended)
just mock

# Or manually
cd script
RUN_MODE=mock RUST_LOG=info cargo run --release
```

### Run All Tests

```bash
just test
```

## Future Evolution

### Planned Enhancements

1. **Multi-epoch batching**: Use recursive proofs to verify multiple epochs in one proof
2. **Proof caching**: Store and reuse proofs for common requests
3. **Self-hosted prover**: Option to run prover infrastructure for lower latency

### Potential Optimizations

1. **Precomputed circuits**: Pre-generate circuits for common request patterns
2. **Incremental proving**: Update proofs incrementally as new data arrives
3. **Proof aggregation**: Combine multiple proofs into one for even lower costs

## Glossary

| Term              | Definition                                                          |
| ----------------- | ------------------------------------------------------------------- |
| **ZKVM**          | Zero-Knowledge Virtual Machine - executes code and generates proofs |
| **SP1**           | Succinct's ZKVM implementation                                      |
| **Guest**         | Code that runs inside the ZKVM                                      |
| **Host**          | Code that orchestrates the ZKVM execution                           |
| **MPT**           | Merkle-Patricia Trie - Ethereum's state storage structure           |
| **Public Values** | Data committed by the guest, visible in the proof                   |
| **PLONK**         | A proof system that generates small, verifiable proofs              |
| **Epoch**         | A week-aligned timestamp used for voting periods                    |
| **State Root**    | Root hash of Ethereum's state trie at a given block                 |

## Resources

- [SP1 Documentation](https://docs.succinct.xyz/)
- [Succinct Prover Network](https://docs.succinct.xyz/docs/protocol/introduction)
- [Ethereum MPT Specification](https://ethereum.org/en/developers/docs/data-structures-and-encoding/patricia-merkle-trie/)
- [Votemarket Documentation](https://docs.stakedao.org/votemarket)
