# Technical Specification

This document provides in-depth technical details about the Votemarket SP1 ZK verifier architecture, design decisions, and integration points.

## Table of Contents

- [Introduction to Zero-Knowledge Proofs](#introduction-to-zero-knowledge-proofs)
- [Problem Statement](#problem-statement)
- [Solution: ZK Compression](#solution-zk-compression)
  - [Detailed Calldata Comparison](#detailed-calldata-comparison)
- [Architecture](#architecture)
  - [System Components](#system-components)
  - [Data Flow](#data-flow)
- [Design Decisions](#design-decisions)
  - [Public Values Format](#public-values-format)
  - [Trust Model](#trust-model)
  - [Semantic Output Format](#semantic-output-format)
  - [Parallel Verification Paths](#parallel-verification-paths)
  - [Single-Epoch Batching](#single-epoch-batching)
  - [Prover Infrastructure](#prover-infrastructure)
- [Integration with Other Repositories](#integration-with-other-repositories)
- [Future Evolution](#future-evolution)
- [Glossary](#glossary)

## Introduction to Zero-Knowledge Proofs

**Zero-Knowledge proofs** are a cryptographic technique that allows one party (the "prover") to prove to another party (the "verifier") that a statement is true, **without revealing any information beyond the validity of the statement itself**.

In our context:

- **Statement**: "These storage values exist in Ethereum's state at block X"
- **Proof**: A tiny cryptographic proof (~300 bytes) that this statement is true
- **Benefit**: The verifier (smart contract) can trust the values without seeing the full proof data

**Analogy**: Imagine proving you're over 18 without showing your ID. A ZK proof lets you prove the fact without revealing your birthdate, name, or any other information.

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

### Detailed Calldata Comparison

This section provides a comprehensive breakdown of calldata costs for both approaches.

#### MPT Approach (Current Implementation)

For **each user claim**, the current `Verifier.sol` requires:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        MPT CALLDATA BREAKDOWN                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   setPointData(gauge, epoch, proof)      ← Once per gauge per epoch         │
│   ├── Function selector: 4 bytes                                            │
│   ├── gauge address: 32 bytes                                               │
│   ├── epoch: 32 bytes                                                       │
│   └── proof (RLP-encoded MPT path):                                         │
│       └── ~1-3 KB (7-8 trie levels, each node up to 532 bytes)              │
│                                                                             │
│   setAccountData(account, gauge, epoch, proof)  ← Once per user per gauge   │
│   ├── Function selector: 4 bytes                                            │
│   ├── account address: 32 bytes                                             │
│   ├── gauge address: 32 bytes                                               │
│   ├── epoch: 32 bytes                                                       │
│   └── proof (3 storage proofs combined):                                    │
│       ├── lastVote proof: ~1-3 KB                                           │
│       ├── slope proof: ~1-3 KB                                              │
│       └── end proof: ~1-3 KB                                                │
│                                                                             │
│   TOTAL PER USER: ~6-13 KB calldata                                         │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Why MPT proofs are large:**

- Ethereum's MPT has ~7-8 levels on average
- Each branch node contains up to 17 elements (16 branches + value)
- Proofs must include all nodes along the path from root to leaf
- Storage proofs require both account proof + storage slot proof

#### ZK Approach (New Implementation)

The ZK approach uses `ZKVerifier.verifyAndInsert(proofBytes, publicValues)`:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         ZK CALLDATA BREAKDOWN                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   PROOF BYTES (constant size, regardless of batch size):                    │
│   ├── Groth16:  ~256 bytes   (smallest, cheapest on-chain)                  │
│   └── PLONK:    ~800 bytes   (universal setup, no trusted ceremony)         │
│                                                                             │
│   PUBLIC VALUES (scales linearly with users):                               │
│   ├── Header:                                                               │
│   │   ├── stateRoot: 32 bytes                                               │
│   │   └── epoch: 32 bytes                                                   │
│   │                                                                         │
│   ├── PointResult (per gauge):                                              │
│   │   ├── gauge: 32 bytes (address padded)                                  │
│   │   ├── epoch: 32 bytes                                                   │
│   │   └── bias: 32 bytes                                                    │
│   │   └── Subtotal: ~96 bytes per gauge                                     │
│   │                                                                         │
│   └── AccountResult (per user):                                             │
│       ├── account: 32 bytes (address padded)                                │
│       ├── gauge: 32 bytes (address padded)                                  │
│       ├── epoch: 32 bytes                                                   │
│       ├── slope: 32 bytes                                                   │
│       ├── end: 32 bytes                                                     │
│       └── lastVote: 32 bytes                                                │
│       └── Subtotal: ~192 bytes per user                                     │
│                                                                             │
│   FORMULA:                                                                  │
│   Total = proof_size + 64 + (96 × gauges) + (192 × users)                   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

#### Scaling Comparison

**Calldata Size by Batch Size:**

| Users | Gauges | MPT Calldata | ZK (Groth16) | ZK (PLONK) | Improvement |
| ----- | ------ | ------------ | ------------ | ---------- | ----------- |
| 1     | 1      | ~10 KB       | ~0.5 KB      | ~1.0 KB    | **10-20x**  |
| 10    | 5      | ~100 KB      | ~2.7 KB      | ~3.3 KB    | **30-37x**  |
| 50    | 10     | ~500 KB ❌   | ~11 KB       | ~11.5 KB   | **43-45x**  |
| 100   | 20     | ~1 MB ❌     | ~22 KB       | ~22.5 KB   | **45-46x**  |
| 200   | 30     | ~2 MB ❌     | ~44 KB       | ~44.5 KB   | **45x**     |

❌ = Exceeds transaction size limit (~128 KB)

**Key Insight**: The ZK proof is constant-size (~256-800 bytes), so adding more users only adds ~192 bytes per user instead of ~10 KB per user.

```
MPT scaling:    calldata ≈ N × 10 KB           (linear, steep slope)
ZK scaling:     calldata ≈ 0.5 KB + N × 0.2 KB (linear, gentle slope)
```

#### Gas Cost Comparison

| Operation            | MPT Gas      | ZK Gas (Groth16) | ZK Gas (PLONK) |
| -------------------- | ------------ | ---------------- | -------------- |
| Proof verification   | N/A (inline) | ~230k            | ~300k          |
| Per-user data insert | ~50k         | ~50k             | ~50k           |
| **1 user total**     | ~250k        | ~280k            | ~350k          |
| **10 users total**   | ~2.5M        | ~730k            | ~800k          |
| **50 users total**   | ~12.5M       | ~2.7M            | ~2.8M          |
| **100 users total**  | ~25M         | ~5.2M            | ~5.3M          |

> **Note**: For MPT, the **calldata limit (~128 KB) is the bottleneck**, not gas. 50 users would require ~500 KB calldata (exceeds limit), even though the gas (~12.5M) fits within a block.

**Why ZK is more gas-efficient at scale:**

- MPT verification is O(N) - each proof verified separately on-chain
- ZK verification is O(1) - one proof covers all users
- The constant verification cost (~230-300k) is amortized across all users

#### Proof Type Comparison

| Aspect           | Groth16                        | PLONK                   |
| ---------------- | ------------------------------ | ----------------------- |
| Proof size       | ~256 bytes                     | ~800 bytes              |
| Verification gas | ~230k                          | ~300k                   |
| Setup            | Trusted ceremony (per-circuit) | Universal (one-time)    |
| Proving time     | Faster                         | Slightly slower         |
| Best for         | Production (smallest proofs)   | Development/flexibility |

Only **PLONK** is supported for the moment.

## Architecture

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
                            ┌─────────────────────────────┘
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

### Public Values Format

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
