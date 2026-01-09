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
