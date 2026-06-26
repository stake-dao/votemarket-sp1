//! Votemarket SP1 ZK proof orchestration.
//!
//! This is the entry point for generating ZK proofs that verify
//! Ethereum storage values for the Votemarket protocol.

mod config;
mod helpers;
mod input;
mod proof;
mod protocol;
mod rpc;
mod toolkit;
mod types;

use alloy_primitives::U256;
use sp1_sdk::network::signer::NetworkSigner;
use sp1_sdk::{Elf, HashableKey, ProveRequest, Prover, ProverClient, ProvingKey, SP1Stdin};
use std::{
    env, fs,
    path::{Path, PathBuf},
};

use config::{ProofKind, ProofSource, RunMode};
use helpers::{
    decode_abi_public_values, decode_hex_bytes, parse_optional_bool_env, resolve_rpc_url,
};
use input::{build_input_from_rpc, build_input_from_toolkit, expand_requests};
use proof::persist_proof;
use rpc::{fetch_block_state_root, fetch_latest_block_number, fetch_proofs};
use toolkit::{ensure_input_json, run_toolkit};
use types::HostInput;

///////////////////////////////////////////////
// CONSTANTS
///////////////////////////////////////////////

const DEFAULT_ELF_REL_PATHS: [&str; 3] = [
    "../program/elf/riscv64im-succinct-zkvm-elf",
    "../target/elf-compilation/riscv64im-succinct-zkvm-elf/release/program",
    "../target/elf-compilation/riscv64im-succinct-zkvm-elf/debug/program",
];
const ONE_WEEK_SECONDS: u64 = 7 * 24 * 60 * 60;

///////////////////////////////////////////////
// ELF LOADING
///////////////////////////////////////////////

fn load_elf() -> Vec<u8> {
    let mut candidates: Vec<String> = Vec::new();
    if let Ok(custom_path) = env::var("SP1_ELF_PATH") {
        candidates.push(custom_path);
    }
    candidates.extend(DEFAULT_ELF_REL_PATHS.iter().map(|path| path.to_string()));

    let mut errors = Vec::new();
    for candidate in candidates {
        let path = resolve_elf_path(&candidate);
        match fs::read(&path) {
            Ok(bytes) => return bytes,
            Err(err) => errors.push(format!("{}: {}", path.display(), err)),
        }
    }

    panic!("Failed to read SP1 ELF. Tried:\n{}", errors.join("\n"));
}

fn resolve_elf_path(path: &str) -> PathBuf {
    let path = PathBuf::from(path);
    if path.is_absolute() {
        path
    } else {
        Path::new(env!("CARGO_MANIFEST_DIR")).join(path)
    }
}

///////////////////////////////////////////////
// MAIN
///////////////////////////////////////////////

#[tokio::main]
async fn main() {
    sp1_sdk::utils::setup_logger();
    dotenvy::dotenv().ok();

    // Quick mode: just print the VKEY and exit (no proof generation needed)
    if parse_optional_bool_env("VKEY_ONLY").unwrap_or(false) {
        env::set_var("SP1_PROVER", "cpu");
        let client = ProverClient::from_env().await;
        let pk = client
            .setup(Elf::from(load_elf()))
            .await
            .expect("Failed to setup prover");
        let vk = pk.verifying_key();
        println!("Program VKEY: {}", vk.bytes32());
        return;
    }

    let run_mode = RunMode::from_env();
    let proof_kind = ProofKind::from_env();
    let proof_source = ProofSource::from_env();
    let verify_proof = parse_optional_bool_env("VERIFY_PROOF").unwrap_or(false);

    let mut host_input = HostInput::load().expect("Invalid host input");
    let (rpc_url, rpc_env_name) =
        resolve_rpc_url(host_input.chain_id).expect("Missing RPC_URL or chain RPC env");

    let http_client = reqwest::Client::new();

    // Resolve block number - fetch latest if not specified
    // When using "latest", we subtract a few blocks to avoid race conditions
    // with load-balanced RPC nodes that may have slightly different chain tips
    const BLOCK_SAFETY_MARGIN: u64 = 3;
    let block_number = match host_input.block_number {
        Some(bn) => bn,
        None => {
            println!("BLOCK_NUMBER not set, fetching latest block...");
            let latest = fetch_latest_block_number(&http_client, &rpc_url)
                .await
                .expect("Failed to fetch latest block number");
            println!(
                "Latest block: {}, using: {}",
                latest,
                latest.saturating_sub(BLOCK_SAFETY_MARGIN)
            );
            latest.saturating_sub(BLOCK_SAFETY_MARGIN)
        }
    };
    // Update host_input with resolved block number so toolkit gets the correct value
    host_input.block_number = Some(block_number);
    println!("Using block number: {block_number}");

    // When using toolkit, use the toolkit's hardcoded slots instead of env/input slots.
    // This ensures the slots match what the toolkit used when generating proofs.
    if matches!(proof_source, ProofSource::Toolkit) {
        if let Some(toolkit_slots) = host_input.protocol.toolkit_slots() {
            println!(
                "Using toolkit slots for protocol {:?}: weight={}, last_vote={}, slope={}",
                host_input.protocol,
                toolkit_slots.weight_mapping_slot,
                toolkit_slots.last_vote_mapping_slot,
                toolkit_slots.user_slope_mapping_slot
            );
            host_input.slots = toolkit_slots;
        } else {
            eprintln!(
                "Warning: No toolkit slots defined for protocol {:?}, using input slots",
                host_input.protocol
            );
        }
    }

    // Create ProverClient - use network mode for PLONK/Groth16 proofs
    let use_network = matches!(
        (&run_mode, &proof_kind),
        (RunMode::Prove, ProofKind::Plonk | ProofKind::Groth16)
    );

    if use_network {
        println!(
            "Using Succinct Prover Network for {} proof...",
            proof_kind.as_str()
        );
        // Set environment variables for network prover
        env::set_var("SP1_PROVER", "network");

        // Debug: Print the address being used for network authentication
        if let Ok(pk) = env::var("NETWORK_PRIVATE_KEY") {
            match NetworkSigner::local(&pk) {
                Ok(signer) => println!("Network requester address: {:?}", signer.address()),
                Err(e) => eprintln!("Warning: Could not parse NETWORK_PRIVATE_KEY: {e}"),
            }
        } else {
            eprintln!("Warning: NETWORK_PRIVATE_KEY not set");
        }
    } else {
        env::set_var("SP1_PROVER", "cpu");
    }

    // Use from_env() which reads SP1_PROVER and NETWORK_PRIVATE_KEY
    let client = ProverClient::from_env().await;
    let mut stdin = SP1Stdin::new();
    let elf: Elf = load_elf().into();

    let (state_root, timestamp) = fetch_block_state_root(&http_client, &rpc_url, block_number)
        .await
        .expect("Failed to fetch block state root");

    let epoch = host_input
        .epoch_override
        .unwrap_or_else(|| (timestamp / ONE_WEEK_SECONDS) * ONE_WEEK_SECONDS);

    let requests = expand_requests(&host_input, epoch).expect("Failed to expand requests");

    // Collect all slots for RPC fetch
    let mut all_slots: Vec<U256> = Vec::new();
    for request in &requests {
        for slot in &request.slots {
            all_slots.push(slot.slot);
        }
    }

    let input = match proof_source {
        ProofSource::Rpc => {
            let proof = fetch_proofs(
                &http_client,
                &rpc_url,
                host_input.gauge_controller,
                block_number,
                &all_slots,
            )
            .await
            .expect("Failed to fetch proofs");

            build_input_from_rpc(
                state_root,
                epoch,
                host_input.protocol,
                host_input.gauge_controller,
                &requests,
                proof,
            )
            .expect("Failed to build input")
        }
        ProofSource::Toolkit => {
            let input_path =
                ensure_input_json(&host_input, epoch).expect("Failed to create input JSON");
            let bundle =
                run_toolkit(&input_path, rpc_env_name, &rpc_url).expect("Failed to run toolkit");

            build_input_from_toolkit(
                state_root,
                epoch,
                host_input.protocol,
                host_input.gauge_controller,
                &requests,
                bundle,
            )
            .expect("Failed to build toolkit input")
        }
    };

    stdin.write(&input);

    println!("Input prepared:");
    println!("  Block: {block_number}");
    println!("  Epoch: {epoch}");
    println!("  State root: {:?}", input.state_root);
    println!("  Point requests: {}", input.point_requests.len());
    for (i, req) in input.point_requests.iter().enumerate() {
        println!("    [{}] gauge={}", i, req.gauge);
    }
    println!("  Account requests: {}", input.account_requests.len());
    for (i, req) in input.account_requests.iter().enumerate() {
        println!("    [{}] account={} gauge={}", i, req.account, req.gauge);
    }

    match run_mode {
        RunMode::Execute => {
            println!("Executing in mock mode...");
            let (public_values, report) =
                client.execute(elf, stdin).await.expect("Execution failed");
            println!("Execution successful!");

            // Decode ABI-encoded public values (raw() returns hex string)
            let raw_bytes =
                decode_hex_bytes(&public_values.raw()).expect("Failed to decode hex public values");
            let output =
                decode_abi_public_values(&raw_bytes).expect("Failed to decode public values");

            println!("Cycles: {}", report.total_instruction_count());
            println!("Output:");
            println!("  State root: {:?}", output.state_root);
            println!("  Epoch: {}", output.epoch);
            println!("  Point results: {}", output.point_results.len());
            for (i, res) in output.point_results.iter().enumerate() {
                println!(
                    "    [{}] gauge={} bias={} protocol_id={} controller={}",
                    i, res.gauge, res.bias, res.protocol_id, res.gauge_controller
                );
            }
            println!("  Account results: {}", output.account_results.len());
            for (i, res) in output.account_results.iter().enumerate() {
                println!(
                    "    [{}] account={} gauge={} slope={} end={} last_vote={} protocol_id={} controller={}",
                    i,
                    res.account,
                    res.gauge,
                    res.slope,
                    res.end,
                    res.last_vote,
                    res.protocol_id,
                    res.gauge_controller
                );
            }
        }
        RunMode::Prove => {
            println!("Generating proof (mode: {})...", proof_kind.as_str());
            let pk = client.setup(elf).await.expect("Failed to setup prover");
            let vk = pk.verifying_key();

            // Print the verification key (PROGRAM_VKEY for Solidity contract)
            println!("Program VKEY: {}", vk.bytes32());

            let proof = match proof_kind {
                ProofKind::Core => client.prove(&pk, stdin).await,
                ProofKind::Compressed => client.prove(&pk, stdin).compressed().await,
                ProofKind::Plonk => client.prove(&pk, stdin).plonk().await,
                ProofKind::Groth16 => client.prove(&pk, stdin).groth16().await,
            }
            .expect("Proof generation failed");

            if verify_proof {
                client
                    .verify(&proof, vk, None)
                    .expect("Proof verification failed");
                println!("Proof verification succeeded");
            }

            // Decode ABI-encoded public values (raw() returns hex string)
            let raw_bytes = decode_hex_bytes(&proof.public_values.raw())
                .expect("Failed to decode hex public values");
            let output =
                decode_abi_public_values(&raw_bytes).expect("Failed to decode public values");

            println!("Proof generated!");
            println!("Output:");
            println!("  State root: {:?}", output.state_root);
            println!("  Epoch: {}", output.epoch);
            println!("  Point results: {}", output.point_results.len());
            println!("  Account results: {}", output.account_results.len());

            let program_vkey = vk.bytes32();
            persist_proof(program_vkey, proof_kind, &proof, output)
                .expect("Failed to persist proof");
        }
    }
}
