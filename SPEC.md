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
- [Security Analysis: ZK vs MPT Attack Surface](#security-analysis-zk-vs-mpt-attack-surface)
  - [Shared Root of Trust](#shared-root-of-trust)
  - [What the ZK Path Removes](#what-the-zk-path-removes)
  - [What the ZK Path Adds](#what-the-zk-path-adds)
  - [Malicious-Actor Matrix](#malicious-actor-matrix)
  - [Anticipated Objections](#anticipated-objections)
  - [Failure Modes and Blast Radius](#failure-modes-and-blast-radius)
  - [Open Items](#open-items)
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
| Calldata per claim    | ~3-10KB      | ~256 bytes      | **~12-40x smaller** |
| Max claims per tx     | ~40          | **Unlimited\*** | **Unbounded**    |
| Gas cost (100 claims) | ~25M gas     | ~5.3M gas       | **~5x cheaper**  |
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
│   │   ├── bias: 32 bytes                                                    │
│   │   ├── protocolId: 32 bytes (uint8 padded)                               │
│   │   └── gaugeController: 32 bytes (address padded)                        │
│   │   └── Subtotal: ~160 bytes per gauge                                    │
│   │                                                                         │
│   └── AccountResult (per user):                                             │
│       ├── account: 32 bytes (address padded)                                │
│       ├── gauge: 32 bytes (address padded)                                  │
│       ├── epoch: 32 bytes                                                   │
│       ├── slope: 32 bytes                                                   │
│       ├── end: 32 bytes                                                     │
│       ├── lastVote: 32 bytes                                                │
│       ├── protocolId: 32 bytes (uint8 padded)                               │
│       └── gaugeController: 32 bytes (address padded)                        │
│       └── Subtotal: ~256 bytes per user                                     │
│                                                                             │
│   FORMULA:                                                                  │
│   Total = proof_size + 64 + (160 × gauges) + (256 × users)                  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

#### Scaling Comparison

**Calldata Size by Batch Size:**

| Users | Gauges | MPT Calldata | ZK (Groth16) | ZK (PLONK) | Improvement |
| ----- | ------ | ------------ | ------------ | ---------- | ----------- |
| 1     | 1      | ~10 KB       | ~0.7 KB      | ~1.3 KB    | **8-14x**   |
| 10    | 5      | ~100 KB      | ~3.7 KB      | ~4.2 KB    | **24-27x**  |
| 50    | 10     | ~500 KB ❌   | ~14.7 KB     | ~15.3 KB   | **33-34x**  |
| 100   | 20     | ~1 MB ❌     | ~29 KB       | ~29.7 KB   | **34x**     |
| 200   | 30     | ~2 MB ❌     | ~56 KB       | ~57 KB     | **35x**     |

❌ = Exceeds transaction size limit (~128 KB)

**Key Insight**: The ZK proof is constant-size (~256-800 bytes), so adding more users only adds ~256 bytes per user instead of ~10 KB per user.

```
MPT scaling:    calldata ≈ N × 10 KB            (linear, steep slope)
ZK scaling:     calldata ≈ 0.7 KB + N × 0.26 KB (linear, gentle slope)
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

Both are wired in the host (`just prove` for PLONK, `just prove-groth16`). **PLONK** is the production default (`PROOF_KIND=plonk`).

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
    address gauge;           // Gauge address
    uint256 epoch;           // Epoch for this data point
    uint256 bias;            // Total votes (points_weight[gauge][epoch].bias)
    uint8   protocolId;      // Protocol enum value used for slot derivation
    address gaugeController; // Account the proof was verified against
}

struct AccountResult {
    address account;         // Voter address
    address gauge;           // Gauge voted for
    uint256 epoch;           // Epoch for this data point
    uint256 slope;           // Vote decay rate
    uint256 end;             // When vote expires
    uint256 lastVote;        // Last vote timestamp (0 for Pendle)
    uint8   protocolId;      // Protocol enum value used for slot derivation
    address gaugeController; // Account the proof was verified against
}
```

The `proof_bytes` and `public_values` from the proof artifacts are what get submitted on-chain.

### Trust Model

The ZK circuit receives a `state_root` as input and trusts it implicitly. It does not validate the state root against a block hash inside the circuit. Instead, **validation happens on-chain**: the `ZKVerifier` contract checks that the proof's `state_root` matches the one stored in the Oracle for the given epoch (`_validateStateRoot`, reverting `EPOCH_NOT_SET` or `STATE_ROOT_MISMATCH`).

This design reuses the existing trust anchor. The Oracle stores one block header per epoch, populated by a governance-authorized block-number provider (the same L1→L2 blockhash pipeline the MPT path relies on). The ZK path anchors on that same root of trust. It also introduces new trust assumptions of its own (proof-system soundness, the in-circuit MPT library, an owner-controlled verifier contract), analyzed exhaustively in [Security Analysis: ZK vs MPT Attack Surface](#security-analysis-zk-vs-mpt-attack-surface).

**What the circuit proves, exactly.** The proof statement is self-contained: "given this 32-byte `state_root` and this `epoch` (both prover-supplied), the account at `gauge_controller` exists in the state trie, and its storage holds value V at the slot canonically derived in-circuit from `(protocol_id, gauge, account, epoch)`". Everything else is deliberately NOT verified in-circuit and is delegated to on-chain checks:

| Not verified in-circuit          | Delegated to                                             |
| -------------------------------- | -------------------------------------------------------- |
| State root belongs to a real block | On-chain compare vs `Oracle.epochBlockNumber(epoch)`   |
| Chain identity (mainnet)         | Same anchor (only mainnet roots are registered)          |
| Epoch matches the block timestamp | Same anchor (one block header per epoch)                |
| `gauge_controller` is legitimate | On-chain `canonicalController` whitelist                 |

The circuit commits no chain id, block number, or block hash. The `(state_root, epoch)` pair is the entire binding, and it holds because the Oracle stores exactly one header per epoch: a proof against the wrong root reverts `STATE_ROOT_MISMATCH`, a proof for an unregistered epoch reverts `EPOCH_NOT_SET`, and a result whose `epoch` field diverges from the committed header epoch reverts `EPOCH_MISMATCH`.

**State-root semantics (differs from the legacy verifiers).** The circuit verifies the gauge-controller account proof against the full **block state root** and extracts the storage root internally. The legacy MPT verifiers instead overwrite `epochBlockNumber[epoch].stateRootHash` with the gauge controller's **storage root** before storing it (`Verifier.sol::_registerBlockHeader`). The two paths therefore cannot share a single Oracle epoch entry: the ZK path requires its epoch anchor to be registered with the true block state root. In the tested wiring, the ZK path runs against a dedicated Oracle where `ZKVerifier` is the sole authorized data provider, which also isolates ZK writes from MPT writes.

**Storage-slot binding (in-circuit).** The circuit derives each storage slot itself from `(protocol_id, gauge, account, epoch)` using the canonical per-protocol layout, instead of trusting a host-supplied slot. This binds the committed labels (gauge / account / epoch) to the verified storage key: a value proven at one slot cannot be relabeled under another (a mismatched label resolves to an exclusion proof and reads zero). An unknown `protocol_id` is rejected (fail-closed), and the protocol's mapping slots are circuit constants, not request inputs. The host computes the same slots only to fetch Merkle proofs; it no longer passes them into the circuit.

**Account binding (in-circuit commit + on-chain whitelist).** The `gauge_controller` account that each proof is verified against is host-supplied, but the circuit commits the `(protocol_id, gauge_controller)` pair into every result in the public values. On-chain, `ZKVerifier` maintains an owner-gated `canonicalController[protocolId]` whitelist and rejects any result whose committed controller does not match the canonical entry (or whose protocol entry is unset). A prover therefore cannot substitute an attacker-deployed contract whose storage mimics the gauge-controller layout: the proof would carry the wrong committed controller and revert `BAD_CONTROLLER`.

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

- **PointResult**: Contains `gauge`, `epoch`, and `bias` (total votes for a gauge), plus the binding pair `protocolId` / `gaugeController`
- **AccountResult**: Contains `account`, `gauge`, `epoch`, `slope`, `end`, and `lastVote` (user's vote data), plus the binding pair `protocolId` / `gaugeController`

This approach has several benefits:

1. **Readability**: The output is self-documenting. You can understand what each field means without knowing Ethereum storage layouts
2. **On-chain efficiency**: The Solidity decoder directly unpacks into Oracle-compatible structs
3. **Type safety**: Fields have explicit types rather than being raw `uint256` values
4. **Protocol awareness**: The circuit handles protocol-specific differences (e.g., Pendle lacks `lastVote`)

**Semantic means decoded, not copied, and Pendle is the case that proves it.** Every other supported protocol stores `slope` and `end` as their own words, so the circuit commits the two verified slot values directly. Pendle does not: its `VotingController` stores `UserPoolData { uint64 weight; VeBalance { uint128 bias; uint128 slope; } }`, i.e. `weight` alone in the user-vote slot and the packed `VeBalance` in the next one, and it stores no expiry at all. So for Pendle the circuit commits `slope = VeBalance.slope` (the high 128 bits of the second word) and derives `end = bias / slope`, the point at which the linearly decaying vote reaches zero. Both come out of the second word; the first word's `weight` is proven but is not a committed output.

This matters because the two words are individually well-formed `uint256`s: committing them raw is not a proof failure, it is a proof of the wrong values. `PendleOracleLens` reads `end` as a decay expiry (`epoch >= end` means spent) and computes `slope * (end - epoch)`, so a raw packed word (~1.8e54) reads as a vote that never expires with an absurd weight. The parity target is `VerifierPendle._extractUserSlope` on the MPT path, which computes the same `bias / slope` in the same integer domain. Any new protocol whose storage packs or derives its vote data must be decoded here the same way, not passed through.

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

## Security Analysis: ZK vs MPT Attack Surface

This section is a factual comparison of the two verification paths, written for reviewers who know the MPT path and are evaluating whether the ZK path enlarges the attack surface. The honest answer is: the ZK path keeps the same root of trust, removes the on-chain Solidity MPT stack from its trusted computing base, and adds a set of new trust assumptions (proof-system soundness, an off-chain MPT library, an owner-controlled verifier contract, a permissioned relayer). Each is enumerated below with its exact bound. Nothing here claims the ZK path is strictly safer, it is a different trade with a known shape.

### Shared Root of Trust

Both paths anchor on the same two governance-controlled roots, so neither is "more trustless" at the foundation:

1. **The per-epoch block anchor.** `Oracle.epochBlockNumber(epoch)` is written only by a governance-authorized block-number provider (`Oracle.sol:94-99`). Both paths accept whatever root that provider registers. A compromised provider forges data on either path.
2. **Oracle governance.** `setAuthorizedDataProvider` is `onlyGovernance` (`Oracle.sol:138-140`), and `Oracle.insertPoint` / `insertAddressEpochData` have no overwrite guard at the Oracle layer. Governance can authorize an arbitrary writer and overwrite any slot on either path. This pre-existing full-trust root is unchanged by the ZK path.

The Oracle write surface of the ZK path is a strict subset of the MPT path's: `ZKVerifier` calls only `insertPoint` and `insertAddressEpochData`, never `insertBlockNumber` (the MPT verifier registers block headers, the ZK verifier does not).

### What the ZK Path Removes

For ZK writes, the entire on-chain Solidity MPT/RLP stack (`StateProofVerifier`, `MerklePatriciaProofVerifier`, `RLPReader`, `RLPDecoder`) is out of the trusted computing base. `ZKVerifier` imports `StateProofVerifier` only for the `BlockHeader` struct type and never calls its verification functions. A bug in the Solidity MPT library affects only the MPT path.

The exploitability profile also changes. The MPT write entrypoints (`setPointData`, `setAccountData`, `setBlockData`) are permissionless, so a soundness bug in the Solidity MPT verification is exploitable by anyone, immediately. On the ZK path, submission is gated by the relayer allowlist (v1), so a circuit soundness bug requires an allowlisted submitter to exploit.

### What the ZK Path Adds

Enumerated honestly, in decreasing order of concern:

**1. In-circuit MPT library soundness (`eth_trie` 0.4.0).** The circuit verifies account and storage proofs with the third-party Rust crate [`eth_trie`](https://github.com/ethereum/eth-trie.rs) (`program/src/main.rs:225`, `:252`), replacing the audited in-repo Solidity. The SNARK proves the guest **executed faithfully**, not that the guest's MPT logic is **correct**: a false-accept bug or backdoor in `eth_trie` would produce a cryptographically valid proof over wrong data that passes every on-chain check. This is the single most severe new surface, because the failure mode is silent (masked by a valid proof) where a Solidity bug is at least on-chain-inspectable. The crate version is pinned in `Cargo.lock` with checksums, which defends against registry substitution but not against the pinned version itself being buggy. Bound: a false-accept still cannot escape the on-chain binds, so forged values are limited to the whitelisted controller and the registered `(state_root, epoch)`. An independent review of the circuit and of `eth_trie`'s proof verification is an open item (see [Open Items](#open-items)).

**2. Proof-system soundness (SP1 zkVM + BN254 PLONK/Groth16 wrap).** On-chain acceptance rests entirely on `SP1_VERIFIER.verifyProof` succeeding. There is no on-chain re-execution of the guest logic. If SP1's STARK, its recursion, or the BN254 SNARK wrap (including PLONK's universal KZG setup or Groth16's circuit-specific setup) were unsound, a forged proof would pass. These are external assumptions inherited from Succinct's stack, they have no analogue on the MPT path.

**3. The Succinct verifier gateway (third-party, upgradeable).** The deployed `SP1_VERIFIER` is Succinct's verifier gateway at `0x3B6041173B80E77f038f3F2C0f9744f04837185e` (pinned in `@address-book` `ExternalUniversal.sol`). Its address is immutable in `ZKVerifier`, but the gateway itself routes `proofBytes` by a 4-byte version selector to Succinct-managed verifier implementations and is administered by Succinct. Gateway governance can add or freeze routes. A malicious route breaks soundness, a frozen route breaks liveness. The MPT path has no external upgradeable dependency.

**4. The `ZKVerifier` owner (a new full-forgery role).** The legacy MPT verifier is immutable and ownerless: every parameter is set at construction, there are no admin functions, zero post-deploy admin surface. `ZKVerifier` is `Ownable` with three levers, each a single transaction with no timelock:

- `updateProgramVKey`: swap the accepted circuit. A compromised owner sets a vKey for an attacker circuit, sets `canonicalController` to any address, and can then write arbitrary values that pass every check (the state root is public, so the attacker circuit simply commits the real one).
- `setAuthorizedRelayer`: widen or empty the submitter set (the empty set is the documented emergency kill switch).
- `setCanonicalController`: repoint a protocol at any account.

This is the largest governance-surface delta versus the MPT path and the main reason the v1 deployment is a trusted-submitter shadow mode. The deployed vKey matching the audited `.vkey.prod` is a **procedural** guarantee (deploy-time argument, CI-verified in the repo), not an on-chain invariant.

**5. The relayer allowlist (permissioned submission).** MPT submission is permissionless, ZK submission is not. The allowlist gates WHO can call, not WHAT gets written: a malicious allowlisted relayer still cannot insert false data, because the proof, state-root, controller, and epoch checks all bind independently. Its effect is therefore liveness and censorship (a relayer set that stalls halts ZK writes), plus the exploit-population narrowing noted above. The permissionless MPT path remains as fallback.

### Malicious-Actor Matrix

Worst case per compromised component. "Liveness" means proofs fail to be produced or revert on-chain, no wrong value is accepted.

| Compromised component | Worst case | Why it is bounded |
| --- | --- | --- |
| Ethereum RPC | Liveness | Fake state root fails `STATE_ROOT_MISMATCH` on-chain |
| Python toolkit subprocess | Liveness, **plus `NETWORK_PRIVATE_KEY` theft** | It cannot forge a value (proofs re-verified in-circuit, slots re-derived in-circuit) and it cannot read the key from its environment (`env_clear` plus a closed allowlist). But it runs as the same uid as the prover, so it can `open("script/.env")` and read the key off disk. Escalates to the row below. Closing it needs a uid or filesystem boundary between prover and toolkit, which this process model does not draw |
| Host machine / `INPUT_JSON` / env vars | Liveness + selection | Committed values all re-verified, but host chooses WHICH requests to prove (censorship, not forgery) |
| Guest ELF substitution (`SP1_ELF_PATH`) | Liveness | Different ELF yields a different vKey, `verifyProof` rejects |
| Prover network operator | Liveness (withhold) | Cannot forge (soundness), inputs are public Ethereum data so nothing secret is learned |
| `NETWORK_PRIVATE_KEY` theft | Financial loss on the prover network | No on-chain authority, unrelated to the relayer allowlist |
| Allowlisted relayer | Liveness (censor) | Cannot alter proven values, `VALUE_DIVERGENCE` blocks overwriting existing entries with different values |
| `ZKVerifier` owner key | **Full forgery** | Not bounded. Mitigations: v1 shadow mode, multisig/timelock ownership (open item) |
| Block-number provider | **Full forgery (both paths)** | Pre-existing shared trust root, unchanged by ZK |
| Oracle governance | **Full forgery (both paths)** | Pre-existing shared trust root, unchanged by ZK |

### Anticipated Objections

Each objection a reviewer coming from the MPT path is likely to raise, with the factual status.

**"We replace audited Solidity math with a black-box circuit."** Partially true. The on-chain trust surface stays small and auditable (decode, state-root match, controller whitelist, epoch match, divergence guard, all plain Solidity in `ZKVerifier.sol`). The circuit is not a black box: it is ~750 lines of Rust logic (plus ~1300 lines of tests) reproducibly compiled in Docker, with adversarial tests for relabeling, cross-protocol substitution, exclusion proofs, unknown protocol ids, and a golden ABI fixture. What IS true: the guest circuit and its `eth_trie` dependency have not been through an external audit yet, unlike the Solidity path. That audit is an open item, not a solved problem.

**"The vKey is a magic number nobody can re-derive."** False, with a condition. `just vkey-verify` rebuilds the guest ELF inside the pinned Docker image (Rust 1.88.0, SP1 v6.3.0, `linux/amd64`, exact `=x.y.z` dependency pins, committed `Cargo.lock`) and byte-compares the derived vKey against `.vkey.prod` (`0x000e2b1800ec78040f1bbc65afcc6aebb7bd0d73601fc6a50dd6d0ea8a4590ba`). CI runs this on every build. Any reviewer can re-derive it, provided they use the pinned toolchain (native builds can legitimately diverge).

**"The owner can swap the vKey and forge everything."** True, and stated as such in item 4 above. A single owner transaction can redirect proof acceptance to an arbitrary circuit. This is the strongest argument of the skeptical position and the reason for the v1 trusted-submitter shadow mode. The mitigation path is operational (multisig plus timelock on the owner) and is listed in [Open Items](#open-items). Note the MPT path is unaffected by any `ZKVerifier` owner action.

**"Succinct's verifier contract is a third-party dependency we don't control."** True. See item 3 above for the exact shape (upgradeable gateway, Succinct-administered). The exposure is new versus MPT and cannot be waved away, only bounded: verification liveness needs the deployed contract, not Succinct the company, and the MPT path remains as an independent fallback for both liveness and (if the gateway were compromised) integrity triage.

**"The prover network sees and could tamper with our data."** Tampering is prevented by proof verification: a proof over altered inputs either fails `verifyProof` or commits values that are genuinely true for the registered state root. Seeing is a non-issue in this application: every input is public Ethereum state. The ZK property used here is succinctness, not confidentiality. The residual power of the network operator is withholding service.

**"A bug in the Rust MPT crate is invisible until exploited."** True, this is item 1 above and the most serious objection. It deserves a real answer, not reassurance: the failure mode is a valid-looking proof over false data, detection would come only from cross-checking against the MPT path or off-chain monitoring, and the mitigation is an independent audit plus the v1 shadow mode where ZK writes are compared against MPT results before being trusted.

**"Mock mode or dev builds could leak into production."** Structurally impossible on-chain: mock mode (`client.execute()`) produces no proof at all, and a dev-built ELF has a different vKey, so `SP1_VERIFIER.verifyProof` rejects anything it signs. The failure mode of a wrong deployment is total liveness failure (every proof rejected), not forgery.

**"The relayer is a centralization point the MPT path does not have."** True, see item 5. Liveness and censorship only, with the permissionless MPT path as fallback. It is also deliberate v1 defense-in-depth: it narrows who could exploit a hypothetical circuit soundness bug while the system runs in shadow mode.

**"What if Succinct disappears?"** New proof generation stalls (the Prover Network is the current proving backend). Already-registered data and claims are unaffected, on-chain verification needs only the deployed gateway contract, the MPT path keeps working permissionlessly, and the architecture supports self-hosted proving (the guest ELF and host are in this repo).

**"How do we even audit this circuit?"** The audit surface is: `program/src/main.rs` (~270 lines of logic plus ~900 lines of tests), `shared/src/protocol.rs` (~360 lines, slot derivation), `shared/src/lib.rs` (~125 lines, boundary types), the `eth_trie` crate's `verify_proof`, and the ABI encoding contract with `ZKVerifier._decodePublicValues`. The build is reproducible byte-for-byte via Docker, so an auditor can bind the reviewed source to the deployed vKey. The adversarial test suite (relabel-to-zero, cross-protocol, fail-closed paths) documents the intended security properties as executable assertions.

### Failure Modes and Blast Radius

**Circuit soundness bug (ZK path).** A crafted proof could commit false values for the whitelisted controller under the registered state root. In v1, only an allowlisted relayer can submit it, and `VALUE_DIVERGENCE` prevents overwriting slots already filled with different values. Detection: divergence against the MPT path during shadow mode.

**Solidity MPT library bug (MPT path).** Exploitable by anyone immediately (permissionless entrypoints), for any gauge or account. No allowlist narrows the population.

**Cross-path slot poisoning.** The first path to write a `(gauge, epoch)` or `(account, gauge, epoch)` slot locks it: the MPT path reverts `ALREADY_REGISTERED` on any rewrite, the ZK path no-ops on identical values and reverts `VALUE_DIVERGENCE` on different ones. A wrong value written by one path is sticky at the verifier layer. Recovery exists only through governance authorizing a direct Oracle data provider (the Oracle itself has no overwrite guard). The tested deployment avoids the shared-state case entirely by giving the ZK path a dedicated Oracle.

**Redundant-submission semantics (ZK only).** Same-value re-submission is a silent no-op instead of MPT's `ALREADY_REGISTERED` revert. Raw committed biases of 0 and 1 are equivalent at the Oracle layer (both stored as 1, matching the MPT rollover guard). Deliberate, bounded, and documented in `ZKVerifier.sol`.

### Open Items

Honest list of what is not yet closed, for the review discussion:

1. **External audit of the guest circuit and of `eth_trie`'s proof verification.** The adversarial test suite is in-repo and self-authored. Independent review should precede any move from shadow mode to a trusted ZK path (and is a hard prerequisite for a future permissionless v2).
2. **Owner hardening.** `ZKVerifier` ownership should sit behind a multisig and ideally a timelock before the ZK path feeds real claims. `updateProgramVKey` in one EOA transaction is the single sharpest lever in the system.
3. **ZK block registration.** The ZK path needs an epoch anchor carrying the true block state root, which the legacy `setBlockData` flow does not produce (it stores the gauge-controller storage root). The production block-registration wiring for ZK epochs must be specified and reviewed.
4. **vKey deploy binding is procedural.** CI proves `.vkey.prod` matches the source, but nothing on-chain ties the deployed `vKey` to `.vkey.prod`. The deploy script argument and any later `updateProgramVKey` call must be verified against the repo value as an operational checklist item.
5. **Public-values framing.** `_decodePublicValues` skips the first 32 bytes assuming SP1's ABI struct-offset framing. The contract is pinned by a golden fixture test on the Rust side and by the pinned SP1 version, but nothing on-chain asserts the offset word. An SP1 upgrade that changes commit framing must be treated as a breaking, coordinated change (it would also change the vKey).

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
