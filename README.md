# Votemarket SP1 Verifier

A Zero-Knowledge proof system for the Votemarket protocol, replacing expensive on-chain Merkle-Patricia Trie (MPT) verification with constant-size ZK proofs.

## Why ZK?

Votemarket is a cross-chain incentive protocol that distributes rewards based on voting data from Ethereum mainnet. This data must be cryptographically verified on L2 chains before rewards can be claimed.

**The problem**: Proving Ethereum storage values on-chain requires submitting full MPT paths (~3KB per proof). This makes batch claims expensive and limits scalability.

**The solution**: Verify MPT proofs off-chain in a ZK circuit, then submit a single ~300 byte proof that attests to hundreds of verified values.

| Users | Gauges | MPT Calldata | ZK (PLONK) | Improvement |
| ----- | ------ | ------------ | ---------- | ----------- |
| 1     | 1      | ~10 KB       | ~1.0 KB    | **10x**     |
| 10    | 5      | ~100 KB      | ~3.3 KB    | **30x**     |
| 50    | 10     | ~500 KB ❌   | ~11.5 KB   | **43x**     |
| 100   | 20     | ~1 MB ❌     | ~22.5 KB   | **45x**     |
| 200   | 30     | ~2 MB ❌     | ~44.5 KB   | **45x**     |

For detailed technical documentation, see [SPEC.md](./SPEC.md).

## Getting Started

### Prerequisites

1. **Docker** with Docker Compose
2. **Just** (command runner)
3. **Python 3.12+** (for the proof toolkit, matching the Docker image)

```bash
# macOS
brew install just

# Linux
cargo install just
```

That's it! All Rust/SP1 toolchain is handled inside Docker.

### Installation

```bash
git clone https://github.com/stake-dao/votemarket-sp1
cd votemarket-sp1
cp script/.env.example script/.env  # Configure your RPC URL and network key
just build                          # Build Docker image (first time only)
just build-guest                    # Build the circuit
just toolkit-setup                  # Install proof toolkit (generates input.json)
```

Edit `script/.env` with your Ethereum RPC URL and your Succinct Network private key.

### Repository Structure

```
votemarket-sp1/
├── program/    # Guest circuit (runs inside ZKVM)
├── script/     # Host application (proof orchestration)
├── shared/     # Shared types between guest and host
├── output/     # Generated proof artifacts
├── docker/     # Docker configuration for reproducible builds
└── justfile    # Command runner recipes
```

## Quick Commands

Run `just` or `just --list` to see all available commands.

### User Commands (Docker-based, recommended)

```bash
# Build commands
just build          # Build Docker image
just build-guest    # Build the circuit
just vkey           # Get verification key
just vkey-verify    # Verify VKEY matches production
just clean          # Clean Docker caches

# Proof generation (requires input.json, env vars from .env)
just mock ./input.json              # Test without real proof
just prove ./input.json             # Generate PLONK proof
just prove-compressed ./input.json  # Generate proof locally (no network)
```

## Usage

All proof commands require an `input.json` file that specifies the proof parameters. See [Input JSON Format](#input-json-format) for the schema.

### Extract the Program VKEY

The verification key uniquely identifies your compiled circuit. Required for deploying `ZKVerifier` on-chain.

```bash
just vkey
```

> [!TIP]
> The current vkey value used in production is saved in the .vkey.prod file.

**Note**: Any change to `program/src/main.rs`, its dependencies, or the Rust compiler version will produce a different VKEY on rebuild and will require redeploying the contract.

### Generate a Real Proof

For PLONK and Groth16 proofs, the system uses the [Succinct Prover Network](https://docs.succinct.xyz/docs/sp1/prover-network/quickstart). This is required because these proof types need GPU acceleration.

**Setup:**

1. **Generate a requester key**: Create an Ethereum-compatible private key (secp256k1)
2. **Fund your account**: Acquire PROVE tokens and deposit them at https://network.succinct.xyz/
3. **Set the environment variable**: `export NETWORK_PRIVATE_KEY=0x...`

> [!TIP]
> Follow this detailled guide [here](https://docs.succinct.xyz/docs/sp1/prover-network/quickstart)

#### Input JSON Format

For known protocols, `gauge_controller` is optional (auto-detected from `protocol`).

```json
{
  "chain_id": 1,
  "block_number": 23438749,
  "epoch": 1758758400,
  "protocol": "curve",
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

#### Output Artifacts

After running in proof mode, artifacts are saved to `script/output/`:

- `proof.bin`: Binary-serialized proof bundle
- `proof.json`: Human-readable proof data with `proof_bytes` and `public_values_raw` for on-chain submission

## Configuration

### Docker Mode

For Docker-based commands, proof parameters are provided via `input.json`. Environment variables are loaded from `script/.env`:

```bash
# script/.env
ETHEREUM_MAINNET_RPC_URL=https://eth-mainnet.g.alchemy.com/v2/...
NETWORK_PRIVATE_KEY=0x...  # Only needed for PLONK/Groth16 proofs
```

| Variable                   | Description                             | Required for         |
| -------------------------- | --------------------------------------- | -------------------- |
| `ETHEREUM_MAINNET_RPC_URL` | Ethereum RPC endpoint                   | All proof commands   |
| `NETWORK_PRIVATE_KEY`      | Private key for Succinct Prover Network | PLONK/Groth16 proofs |

## Proof Modes

| Mode         | On-chain Verifiable | Use Case       |
| ------------ | ------------------- | -------------- |
| `core`       | No                  | Development    |
| `compressed` | No                  | Testing        |
| `plonk`      | **Yes**             | **Production** |
| `groth16`    | **Yes**             | Production alt |

**Use `PROOF_KIND=plonk` for production.**

<details>

<summary>Contributors Section</summary>

## For Contributors

If you want to contribute, you'll need additional tools:

- Rust (see `rust-toolchain.toml` for version)
- SP1 Toolchain (`sp1up`)

```bash
# Install SP1 toolchain
curl -L https://sp1.succinct.xyz | bash
sp1up
```

Development commands run natively (without Docker) for faster iteration:

```bash
just dev-build        # Build workspace
just dev-build-guest  # Build circuit (may differ from CI!)
just dev-test         # Run all tests
just dev-lint         # Run clippy
just dev-fmt          # Format code
```

> [!WARNING]
> `just dev-build-guest` may produce a different VKEY than CI due to environment differences. Always use `just build-guest` (Docker) for reproducible builds.

### Testing

```bash
# Integration test (Docker)
just mock ./input.json

# Unit tests (for contributors)
just dev-test
just dev-test-guest
just dev-test-script
```

### Toolkit Setup

The toolkit allows fetching proof data from RPC endpoints. It installs from
`toolkit-requirements.lock`, a hash-locked resolution of the whole transitive tree,
so the venv and the Docker image run byte-identical code on the proof path. That
lock is resolved for Python 3.12+; older interpreters resolve a different pandas
and numpy, which is exactly the divergence the lock prevents.

To change the toolkit version, edit the pin in `toolkit-requirements.in`, run
`just toolkit-lock` (needs [uv](https://github.com/astral-sh/uv)), re-verify against
the image, and commit both files together. Never hand-edit the lock.

```bash
just toolkit-setup
source .venv/bin/activate

# Generate proof with toolkit as data source (native mode)
ETHEREUM_MAINNET_RPC_URL=https://... \
GAUGE=0x... \
ACCOUNT=0x... \
just dev-prove-toolkit
```

</details>

## Resources

- [SP1 Documentation](https://docs.succinct.xyz/)
- [Succinct Prover Network](https://docs.succinct.xyz/docs/protocol/introduction)
- [Votemarket Documentation](https://docs.stakedao.org/vm_overview/votemarket)
- [Technical Specification](./SPEC.md)
