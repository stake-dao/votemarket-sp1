# Votemarket SP1 Verifier

This repository contains the Zero-Knowledge (ZK) circuit implementation for the Votemarket protocol using [Succinct SP1](https://succinct.xyz/).

## Overview

The **Votemarket SP1 Verifier** is a ZK Coprocessor designed to offload the verification of Ethereum Storage Proofs from the EVM to a ZK Virtual Machine.

Instead of submitting large Merkle-Patricia Trie (MPT) branches as calldata to the blockchain (which is expensive and limits scalability), this system allows the `Bundler` to submit a single, constant-size ZK proof that attests to the validity of multiple storage slots.

## Rationale

Votemarket relies on cross-chain data (e.g., Curve Gauge weights, user balances) to distribute rewards. Currently, this is achieved via **Oracle-based data population using Storage Proofs**.

### The Problem: Calldata Bottleneck

- **Standard Approach:** Verifying a storage slot on-chain requires submitting the full path of RLP-encoded nodes for both the Account Trie and the Storage Trie.
- **Cost:** A single proof can consume ~2-3KB of calldata.
- **Limitation:** When batching claims for multiple campaigns, the transaction size quickly hits the block gas limit or the max transaction size, capping the number of actions a user can perform in one go.

### The Solution: ZK Compression

By moving the verification logic to a ZKVM (SP1):

1.  **Input:** We feed the raw MPT proofs to the SP1 Guest program off-chain.
2.  **Computation:** The Guest program cryptographically verifies the proofs against a trusted Block Hash.
3.  **Output:** The Guest produces a tiny ZK proof and a list of "Public Values" (the verified storage values).
4.  **On-Chain:** The smart contract verifies the ZK proof (cheap) and trusts the Public Values.

**Result:** We can verify hundreds of storage slots in a single transaction with constant gas overhead.

## Architecture

The project is organized as a Rust workspace:

- **`program/` (Guest, runs inside the ZKVM):**

  - Deterministic logic that **verifies storage proofs**.
  - Input: `(state_root, proofs[])`.
  - Output (public values): `(state_root, results[])`.
  - Think of it as the on-chain verifier logic, but executed inside SP1.

- **`script/` (Host, runs on your machine/server):**

  - Orchestration code that **prepares inputs** and **runs the guest**.
  - Fetches proofs from RPC (or builds mock proofs in dev).
  - Executes the guest in mock mode or generates a ZK proof.
  - Think of it as the client that feeds data to the circuit and reads its output.

- **`shared/`:**
  - Shared data structures (`Input`, `Output`, `StorageProofRequest`) used by both Guest and Host to ensure serialization compatibility.
  - **Input:** `state_root` (bytes32) + list of `(account, slot, account_proof, storage_proof)`.
  - **Output:** `state_root` (bytes32) + list of `(account, slot, value)`.

> **Note:** The `Output` struct is what gets encoded as "Public Values" and passed to the Solidity Verifier.

## Getting Started

### Prerequisites

- Rust
- SP1 Toolchain

```bash
curl -L https://sp1.succinct.xyz | bash
sp1up
```

### Installation

Clone the repository and install dependencies:

```bash
git clone <repo-url>
cd votemarket-sp1
cargo build --release
```

## Usage

### 1. Build the Guest Program (SP1 ELF)

This compiles the Rust logic into a RISC-V ELF binary executable by the ZKVM.

```bash
cd program
cargo prove build
cd ..
```

### 2. Run the Host (Mock Mode)

The current script is configured to run in **Mock Mode** by default. This executes the Guest logic natively on your CPU to verify correctness without generating a heavy ZK proof.

```bash
cd script
RUST_LOG=info cargo run --release
```

### 3. Run the Host (Proof Mode)

Set `RUN_MODE=prove` to generate a real proof. You can choose the proof format and optionally verify the proof locally.

```bash
cd script
RUN_MODE=prove PROOF_KIND=plonk VERIFY_PROOF=true RUST_LOG=info cargo run --release
```

Proof artifacts are saved under `script/output/` by default:

- `proof.bin` (bincode-serialized SP1 proof bundle)
- `proof.json` (proof bytes, public values, and decoded outputs)

You can override the file names with `PROOF_OUTPUT` and `PROOF_JSON`.

#### Output (`proof.json`)

```json
{
  "proof_kind": "plonk|groth16|compressed|core",
  "proof_bytes": "0x... (plonk/groth16 only)",
  "public_values_raw": "0x...",
  "public_values_hash": "0x...",
  "public_values_hash_bn254": "0x...",
  "output": {
    "state_root": "0x...",
    "results": [
      {
        "account": "0x...",
        "slot": "0x...",
        "value": "0x..."
      }
    ]
  }
}
```

- `proof_kind`: proof format (`core`, `compressed`, `plonk`, `groth16`).
- `proof_bytes`: hex-encoded proof bytes for on-chain verifiers (only present for `plonk`/`groth16`).
- `public_values_raw`: hex-encoded bytes committed by the guest (`Output` serialized via `sp1_zkvm::io::commit`).
- `public_values_hash`: SHA-256 hash of `public_values_raw` (hex).
- `public_values_hash_bn254`: BN254 field element encoding of the same digest (hex) used by the Solidity verifiers.
- `output`: decoded public values for convenience.
- `output.state_root`: state root the guest validated against.
- `output.results[]`: list of `(account, slot, value)` storage values proven under that state root.

`proof_bytes` and `public_values_raw` are the values broadcasted on-chain.

### 4. Inputs (Env or JSON)

You can pass inputs via env vars or a JSON file:

```bash
ETHEREUM_MAINNET_RPC_URL=... \
CHAIN_ID=1 \
BLOCK_NUMBER=23438749 \
PROTOCOL=curve \
GAUGE_CONTROLLER=0x... \
GAUGE=0x... \
ACCOUNT=0x... \
WEIGHT_MAPPING_SLOT=0x... \
LAST_VOTE_MAPPING_SLOT=0x... \
USER_SLOPE_MAPPING_SLOT=0x... \
RUST_LOG=info cargo run --release
```

Note: for other chains, set the toolkit-style RPC env var (`ARBITRUM_MAINNET_RPC_URL`, `OPTIMISM_MAINNET_RPC_URL`,
`BASE_MAINNET_RPC_URL`, `POLYGON_MAINNET_RPC_URL`, `BSC_MAINNET_RPC_URL`) and update `CHAIN_ID` accordingly.

Or provide a JSON file that follows the canonical host schema:

```json
{
  "chain_id": 1,
  "block_number": 23438749,
  "epoch": 1758758400,
  "protocol": "curve",
  "gauge_controller": "0x0000000000000000000000000000000000000000",
  "slots": {
    "weight_mapping_slot": "0x00",
    "last_vote_mapping_slot": "0x00",
    "user_slope_mapping_slot": "0x00"
  },
  "requests": [
    {
      "type": "account_data",
      "account": "0x0000000000000000000000000000000000000000",
      "gauge": "0x0000000000000000000000000000000000000000"
    },
    {
      "type": "point_data",
      "gauge": "0x0000000000000000000000000000000000000000"
    }
  ]
}
```

Save it and pass `INPUT_JSON=/path/to/host_input.json`.

### 5. Toolkit Proof Source

To reuse the VoteMarket proof toolkit as the proof input generator, set `PROOF_SOURCE=toolkit`.
The host will generate (or reuse) the host JSON and call `script/toolkit_adapter.py`.
It also forwards the chain-specific RPC env var to the toolkit, so you only set it once in this repo.

Quickstart (after installing the toolkit and setting `ETHEREUM_MAINNET_RPC_URL`):

Install the toolkit into a local Python environment in this repo:

```bash
cd /path/to/votemarket-sp1
python -m venv .venv
source .venv/bin/activate
pip install votemarket-toolkit
```

Or, with `uv`:

```bash
cd /path/to/votemarket-sp1
uv venv .venv
uv pip install votemarket-toolkit
```

Then run from the `votemarket-sp1/script` directory:

```bash
cd /path/to/votemarket-sp1/script
PROOF_SOURCE=toolkit RUN_MODE=prove PROOF_KIND=plonk VERIFY_PROOF=true RUST_LOG=info cargo run --release
```

If the host cannot locate your Python interpreter, set it explicitly:

```bash
export PYTHON_BIN="$(which python)"
```

If you want to use a local checkout of the toolkit instead of the PyPI package:

```bash
export TOOLKIT_ROOT=/path/to/votemarket-proof-toolkit
```

Then rerun the command:

```bash
PROOF_SOURCE=toolkit RUN_MODE=prove PROOF_KIND=plonk VERIFY_PROOF=true RUST_LOG=info cargo run --release
```

Refer to the [VoteMarket Proof Toolkit README](https://github.com/stake-dao/votemarket-proof-toolkit) for further examples and advanced configuration.

Ensure the toolkit RPC env vars are configured (see its README).

### How the two apps relate (end-to-end flow)

1. **Host (`script/`) collects inputs**: state root + MPT proofs (real RPC or mock).
2. **Host runs Guest (`program/`)**: feeds inputs into the ZKVM using the compiled ELF.
3. **Guest verifies proofs**: computes and commits public outputs.
4. **Host reads outputs**: uses them directly (mock mode) or wraps them in a ZK proof.

If you only build `program/`, nothing runs by itself. The `script/` is the entrypoint that drives the flow.

## Testing

To run the unit tests for the MPT verification logic, run the following command:

```bash
cd program
cargo test
cd ..
```
