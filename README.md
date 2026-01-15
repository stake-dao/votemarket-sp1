# Votemarket SP1 Verifier

A Zero-Knowledge proof system for the Votemarket protocol, replacing expensive on-chain Merkle-Patricia Trie (MPT) verification with constant-size ZK proofs.

## Why ZK?

Votemarket is a cross-chain incentive protocol that distributes rewards based on voting data from Ethereum mainnet. This data must be cryptographically verified on L2 chains before rewards can be claimed.

**The problem**: Proving Ethereum storage values on-chain requires submitting full MPT paths (~3KB per proof). This makes batch claims expensive and limits scalability.

**The solution**: Verify MPT proofs off-chain in a ZK circuit, then submit a single ~300 byte proof that attests to hundreds of verified values.

| Metric                | MPT (Before) | ZK (After) |
| --------------------- | ------------ | ---------- |
| Calldata per claim    | ~3KB         | ~10 bytes  |
| Max claims per tx     | ~40          | 500+       |
| Gas cost (100 claims) | ~5M gas      | ~400k gas  |

For detailed technical documentation, see [SPEC.md](./SPEC.md).

## Getting Started

### Prerequisites

1. **Rust** (latest stable)
2. **SP1 Toolchain**

```bash
curl -L https://sp1.succinct.xyz | bash
sp1up
```

3. **Just** (command runner)

```bash
# macOS
brew install just

# Linux
cargo install just
```

4. **Python 3.10+** (for the proof toolkit)

### Installation

```bash
git clone https://github.com/stake-dao/votemarket-sp1
cd votemarket-sp1
just build
just build-guest    # Build the guest code
just toolkit-setup  # Install Python dependencies
```

### Build the Guest Circuit

```bash
just build-guest
```

This compiles the guest code into a RISC-V ELF binary that SP1 can execute.

### Extract the Program VKEY

The verification key uniquely identifies your compiled circuit. Required for deploying `ZKVerifier` on-chain.

```bash
just vkey
```

Output:

```
Program VKEY: 0x00dc92847478212b289df1a1eeddf1a795eac6cd936fc9bdc0ae434c59e75953
```

**Note**: Any change to `program/src/main.rs`, its dependencies, or the Rust compiler version will produce a different VKEY on rebuild and will require redeploying the contract.

## Repository Structure

```
votemarket-sp1/
├── program/    # Guest circuit (runs inside ZKVM)
├── script/     # Host application (proof orchestration)
├── shared/     # Shared types between guest and host
├── output/     # Generated proof artifacts
└── justfile    # Command runner recipes
```

## Quick Commands

Run `just` or `just --list` to see all available commands.

### Common Workflows

```bash
# Development
just build-guest    # Build the circuit
just vkey           # Get verification key
just mock           # Test without real proof

# Production
just prove          # Generate PLONK proof (recommended)
just prove-groth16  # Alternative: Groth16 proof

# External data sources
ETHEREUM_MAINNET_RPC_URL=https://... just prove-rpc
just prove-json ./input.json

# Testing & quality
just test           # Run all tests
just lint           # Check code quality

# Help
just env-help       # Show environment variables
just proof-kinds    # Explain proof formats
```

## Usage

### Mock Mode (Development)

```bash
just mock
```

Executes the guest logic natively without generating a ZK proof. Use for development and testing.

### Generate a Real Proof

```bash
just prove
```

Generates a PLONK proof that can be verified on-chain. The system uses the [Succinct Prover Network](https://docs.succinct.xyz/docs/sp1/prover-network/quickstart) to generate proofs. This requires:

1. **Generate a requester key**: Create an Ethereum-compatible private key
2. **Fund your account**: Acquire PROVE tokens and deposit them at https://network.succinct.xyz/
3. **Set the environment variable**: `export NETWORK_PRIVATE_KEY=0x...`

```bash
# Generate PLONK proof using the network
NETWORK_PRIVATE_KEY=0x... just prove
```

Note: Core and compressed proofs can be generated locally without the network.

### Using the Proof Toolkit

```bash
# Setup (one-time)
just toolkit-setup
source .venv/bin/activate

# Generate proof with toolkit as data source
ETHEREUM_MAINNET_RPC_URL=https://... just prove-toolkit
```

### Output Artifacts

After running in proof mode, artifacts are saved to `output/`:

- `proof.bin`: Binary-serialized proof bundle
- `proof.json`: Human-readable proof data with `proof_bytes` and `public_values_raw` for on-chain submission

## Configuration

### Environment Variables

#### Core Settings

| Variable       | Description                              | Default   |
| -------------- | ---------------------------------------- | --------- |
| `RUN_MODE`     | `mock` or `prove`                        | `mock`    |
| `PROOF_KIND`   | `core`, `compressed`, `plonk`, `groth16` | `plonk`   |
| `VERIFY_PROOF` | Verify proof locally after generation    | `false`   |
| `PROOF_SOURCE` | `rpc` or `toolkit`                       | `toolkit` |
| `INPUT_JSON`   | Path to input JSON file (overrides env)  | -         |

#### Blockchain Settings

| Variable                   | Description                                        | Default    |
| -------------------------- | -------------------------------------------------- | ---------- |
| `ETHEREUM_MAINNET_RPC_URL` | Ethereum RPC endpoint                              | Required   |
| `CHAIN_ID`                 | Chain ID for RPC calls                             | `1`        |
| `BLOCK_NUMBER`             | Block number for proofs                            | Latest     |
| `EPOCH`                    | Override epoch timestamp                           | From block |
| `PROTOCOL`                 | `curve`, `balancer`, `frax`, `fxn`, `pendle`, `yb` | `curve`    |

#### Contract Parameters

| Variable                  | Description                       | Default                         |
| ------------------------- | --------------------------------- | ------------------------------- |
| `GAUGE_CONTROLLER`        | GaugeController address           | Required                        |
| `GAUGE`                   | Gauge address                     | Required                        |
| `ACCOUNT`                 | User account address              | Required                        |
| `WEIGHT_MAPPING_SLOT`     | Storage slot for points_weight    | Protocol default (if available) |
| `LAST_VOTE_MAPPING_SLOT`  | Storage slot for last_user_vote   | Protocol default (if available) |
| `USER_SLOPE_MAPPING_SLOT` | Storage slot for vote_user_slopes | Protocol default (if available) |

**Note**: Storage slot variables are optional for known protocols (`curve`, `balancer`, `frax`, `fxn`, `pendle`, `yb`). The system uses built-in defaults for these protocols.

#### Prover Network

| Variable              | Description                             | Default                    |
| --------------------- | --------------------------------------- | -------------------------- |
| `NETWORK_PRIVATE_KEY` | Private key for Succinct Prover Network | Required for PLONK/Groth16 |

### Succinct Prover Network

For PLONK and Groth16 proofs, the system uses the [Succinct Prover Network](https://docs.succinct.xyz/docs/sp1/prover-network/quickstart). This is required because these proof types need GPU acceleration.

**Setup:**

1. **Generate a requester key**: Create an Ethereum-compatible private key (secp256k1)
2. **Fund your account**: Acquire PROVE tokens and deposit them at https://network.succinct.xyz/
3. **Set the environment variable**: `export NETWORK_PRIVATE_KEY=0x...`

```bash
# Generate PLONK proof using the network
NETWORK_PRIVATE_KEY=0x... just prove

# Generate compressed proof locally (no network needed)
just prove-compressed
```

Core and compressed proofs can be generated locally without the network.

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
    { "type": "point_data", "gauge": "0x..." },
    { "type": "account_data", "account": "0x...", "gauge": "0x..." }
  ]
}
```

## Proof Modes

| Mode         | On-chain Verifiable | Use Case       |
| ------------ | ------------------- | -------------- |
| `core`       | No                  | Development    |
| `compressed` | No                  | Testing        |
| `plonk`      | **Yes**             | **Production** |
| `groth16`    | **Yes**             | Production alt |

**Use `PROOF_KIND=plonk` for production.**

## Testing

```bash
just test           # Run all tests
just test-guest     # Guest circuit tests only
just test-script    # Script tests only
just mock           # Integration test
```

## Resources

- [SP1 Documentation](https://docs.succinct.xyz/)
- [Succinct Prover Network](https://docs.succinct.xyz/docs/protocol/introduction)
- [Votemarket Documentation](https://docs.stakedao.org/votemarket)
- [Technical Specification](./SPEC.md)
