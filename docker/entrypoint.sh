#!/bin/bash
# Entrypoint script for SP1 circuit compilation container

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Fix permissions for mounted volumes (runs as root, then drops to builder)
fix_permissions() {
    # Fix ownership of cargo directories
    chown -R ubuntu:ubuntu /home/ubuntu/.cargo 2>/dev/null || true
    chown -R ubuntu:ubuntu /home/ubuntu/.sp1 2>/dev/null || true

    # Fix ownership of workspace target directory if it exists
    if [ -d /workspace/target ]; then
        chown -R ubuntu:ubuntu /workspace/target 2>/dev/null || true
    fi

    # Pre-create the host-visible ELF export dir as root: on Linux hosts the
    # bind-mounted /workspace is owned by the host uid, so the builder user
    # cannot mkdir inside it (CI failure mode; macOS Docker is permissive)
    mkdir -p /workspace/program/elf
    chown ubuntu:ubuntu /workspace/program/elf
}

# Run permission fixes
fix_permissions

# Execute command as builder user
run_as_builder() {
    exec gosu ubuntu "$@"
}

case "$1" in
    build-guest)
        echo -e "${YELLOW}Building guest circuit...${NC}"
        # SP1 v6 writes the ELF under target/, which is a named volume invisible
        # to the host. Export it to the bind-mounted program/elf/ so host-side
        # tooling (and the host binary's primary ELF probe path) can use it.
        run_as_builder bash -c 'cd /workspace/program && cargo prove build \
            && cp /workspace/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/program /workspace/program/elf/riscv64im-succinct-zkvm-elf \
            && echo "ELF exported to program/elf/riscv64im-succinct-zkvm-elf"'
        ;;

    vkey)
        echo -e "${YELLOW}Extracting VKEY...${NC}"
        run_as_builder bash -c 'cd /workspace/script && VKEY_ONLY=true cargo run --release'
        ;;

    vkey-verify)
        echo -e "${YELLOW}Building guest circuit and verifying VKEY...${NC}"

        # Build the guest first (and export the ELF to the host-visible dir,
        # same as the build-guest case)
        gosu ubuntu bash -c 'cd /workspace/program && cargo prove build \
            && cp /workspace/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/program /workspace/program/elf/riscv64im-succinct-zkvm-elf'

        # Extract VKEY and capture output
        VKEY_OUTPUT=$(gosu ubuntu bash -c 'cd /workspace/script && VKEY_ONLY=true cargo run --release 2>&1')
        GENERATED_VKEY=$(echo "$VKEY_OUTPUT" | grep -oE '0x[a-fA-F0-9]{64}' | head -1)

        # Read expected VKEY
        if [ -f /workspace/.vkey.prod ]; then
            EXPECTED_VKEY=$(cat /workspace/.vkey.prod | tr -d '[:space:]')
        else
            echo -e "${RED}Error: .vkey.prod file not found${NC}"
            exit 1
        fi

        echo ""
        echo "Expected VKEY:  ${EXPECTED_VKEY}"
        echo "Generated VKEY: ${GENERATED_VKEY}"
        echo ""

        if [ "$GENERATED_VKEY" = "$EXPECTED_VKEY" ]; then
            echo -e "${GREEN}VKEY verification passed!${NC}"
            exit 0
        else
            echo -e "${RED}VKEY verification FAILED!${NC}"
            echo "The generated VKEY does not match .vkey.prod"
            exit 1
        fi
        ;;

    shell)
        echo -e "${YELLOW}Starting interactive shell as builder...${NC}"
        run_as_builder /bin/bash
        ;;

    # =========================================================================
    # PROOF GENERATION COMMANDS
    # =========================================================================

    mock)
        echo -e "${YELLOW}Running in mock mode...${NC}"
        run_as_builder bash -c 'cd /workspace/script && RUN_MODE=mock RUST_LOG=info cargo run --release'
        ;;

    mock-debug)
        echo -e "${YELLOW}Running in mock mode with debug output...${NC}"
        run_as_builder bash -c 'cd /workspace/script && RUN_MODE=mock RUST_LOG=debug cargo run --release'
        ;;

    prove)
        echo -e "${YELLOW}Generating PLONK proof...${NC}"
        # Note: VERIFY_PROOF=false because local verification requires Docker-in-Docker
        # The Succinct Network validates the proof, and it will be verified on-chain
        run_as_builder bash -c 'cd /workspace/script && RUN_MODE=prove PROOF_KIND=plonk VERIFY_PROOF=false RUST_LOG=info cargo run --release'
        ;;

    prove-groth16)
        echo -e "${YELLOW}Generating Groth16 proof...${NC}"
        run_as_builder bash -c 'cd /workspace/script && RUN_MODE=prove PROOF_KIND=groth16 VERIFY_PROOF=false RUST_LOG=info cargo run --release'
        ;;

    prove-compressed)
        echo -e "${YELLOW}Generating compressed STARK proof...${NC}"
        run_as_builder bash -c 'cd /workspace/script && RUN_MODE=prove PROOF_KIND=compressed VERIFY_PROOF=false RUST_LOG=info cargo run --release'
        ;;

    prove-core)
        echo -e "${YELLOW}Generating core STARK proof...${NC}"
        run_as_builder bash -c 'cd /workspace/script && RUN_MODE=prove PROOF_KIND=core VERIFY_PROOF=false RUST_LOG=info cargo run --release'
        ;;

    help|--help|-h|"")
        echo "SP1 Circuit Compilation Container"
        echo ""
        echo "Usage: just <command> [input.json]"
        echo ""
        echo "Build Commands:"
        echo "  build-guest     Build the guest circuit (compiles to RISC-V ELF)"
        echo "  vkey            Extract VKEY only"
        echo "  vkey-verify     Build circuit and verify VKEY matches .vkey.prod"
        echo "  shell           Start interactive shell for debugging"
        echo ""
        echo "Proof Generation Commands (require input.json):"
        echo "  mock            Run in mock mode (no ZK proof)"
        echo "  mock-debug      Run in mock mode with debug output"
        echo "  prove           Generate PLONK proof (requires NETWORK_PRIVATE_KEY)"
        echo "  prove-fast      Generate PLONK proof without verification"
        echo "  prove-groth16   Generate Groth16 proof"
        echo "  prove-compressed Generate compressed STARK proof (no network needed)"
        echo "  prove-core      Generate core STARK proof"
        echo ""
        echo "Other:"
        echo "  help            Show this help message"
        echo ""
        echo "Examples:"
        echo "  just build-guest"
        echo "  just mock ./input.json"
        echo "  NETWORK_PRIVATE_KEY=0x... just prove ./input.json"
        ;;

    *)
        # Pass through any other command as builder user
        run_as_builder "$@"
        ;;
esac
