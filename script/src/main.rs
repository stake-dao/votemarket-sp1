use alloy_primitives::{hex, Address, B256, U256};
use serde::{Deserialize, Serialize};
use serde_json::json;
use shared::{Input, Output, StorageProofRequest};
use sha3::{Digest, Keccak256};
use sp1_sdk::{ProverClient, SP1Stdin};
use std::{
    env,
    path::{Path, PathBuf},
    str::FromStr,
};

const DEFAULT_ELF_REL_PATHS: [&str; 3] = [
    "../program/elf/riscv32im-succinct-zkvm-elf",
    "../target/elf-compilation/riscv32im-succinct-zkvm-elf/release/program",
    "../target/elf-compilation/riscv32im-succinct-zkvm-elf/debug/program",
];

const ONE_WEEK_SECONDS: u64 = 7 * 24 * 60 * 60;

fn load_elf() -> Vec<u8> {
    let mut candidates: Vec<String> = Vec::new();
    if let Ok(custom_path) = env::var("SP1_ELF_PATH") {
        candidates.push(custom_path);
    }
    candidates.extend(DEFAULT_ELF_REL_PATHS.iter().map(|path| path.to_string()));

    let mut errors = Vec::new();
    for candidate in candidates {
        let path = resolve_elf_path(&candidate);
        match std::fs::read(&path) {
            Ok(bytes) => return bytes,
            Err(err) => errors.push(format!("{}: {}", path.display(), err)),
        }
    }

    panic!(
        "Failed to read SP1 ELF. Tried:\n{}",
        errors.join("\n")
    );
}

fn resolve_elf_path(path: &str) -> PathBuf {
    let path = PathBuf::from(path);
    if path.is_absolute() {
        path
    } else {
        Path::new(env!("CARGO_MANIFEST_DIR")).join(path)
    }
}

fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    hasher.finalize().into()
}

#[derive(Debug)]
struct HostConfig {
    rpc_url: String,
    block_number: u64,
    gauge_controller: Address,
    gauge: Address,
    account: Address,
    weight_mapping_slot: U256,
    last_vote_mapping_slot: U256,
    user_slope_mapping_slot: U256,
    epoch_override: Option<u64>,
}

impl HostConfig {
    fn from_env() -> Result<Self, String> {
        let rpc_url = require_env("RPC_URL")?;
        let block_number = parse_u64_env("BLOCK_NUMBER")?;
        let gauge_controller = parse_address_env("GAUGE_CONTROLLER")?;
        let gauge = parse_address_env("GAUGE")?;
        let account = parse_address_env("ACCOUNT")?;
        let weight_mapping_slot = parse_u256_env("WEIGHT_MAPPING_SLOT")?;
        let last_vote_mapping_slot = parse_u256_env("LAST_VOTE_MAPPING_SLOT")?;
        let user_slope_mapping_slot = parse_u256_env("USER_SLOPE_MAPPING_SLOT")?;
        let epoch_override = parse_optional_u64_env("EPOCH");

        Ok(Self {
            rpc_url,
            block_number,
            gauge_controller,
            gauge,
            account,
            weight_mapping_slot,
            last_vote_mapping_slot,
            user_slope_mapping_slot,
            epoch_override,
        })
    }
}

#[derive(Debug)]
struct SlotRequest {
    label: &'static str,
    slot: U256,
}

#[derive(Serialize)]
struct RpcRequest<'a> {
    jsonrpc: &'static str,
    id: u64,
    method: &'a str,
    params: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct RpcError {
    code: i64,
    message: String,
}

#[derive(Debug, Deserialize)]
struct RpcResponse<T> {
    result: Option<T>,
    error: Option<RpcError>,
}

#[derive(Debug, Deserialize)]
struct BlockResponse {
    #[serde(rename = "stateRoot")]
    state_root: String,
    #[serde(rename = "timestamp")]
    timestamp: String,
}

#[derive(Debug, Deserialize)]
struct StorageProof {
    #[serde(rename = "proof")]
    proof: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ProofResponse {
    #[serde(rename = "accountProof")]
    account_proof: Vec<String>,
    #[serde(rename = "storageProof")]
    storage_proof: Vec<StorageProof>,
}

async fn rpc_call<T: for<'de> Deserialize<'de>>(
    client: &reqwest::Client,
    url: &str,
    method: &str,
    params: serde_json::Value,
) -> Result<T, String> {
    let request = RpcRequest {
        jsonrpc: "2.0",
        id: 1,
        method,
        params,
    };

    let response = client
        .post(url)
        .json(&request)
        .send()
        .await
        .map_err(|err| format!("RPC request failed: {err}"))?;

    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|err| format!("RPC response read failed: {err}"))?;

    if !status.is_success() {
        return Err(format!("RPC status error {}: {}", status, body));
    }

    let rpc_response: RpcResponse<T> =
        serde_json::from_str(&body).map_err(|err| format!("RPC decode failed: {err}"))?;

    if let Some(error) = rpc_response.error {
        return Err(format!("RPC error {}: {}", error.code, error.message));
    }

    rpc_response
        .result
        .ok_or_else(|| "RPC response missing result".to_string())
}

async fn fetch_block_state_root(
    client: &reqwest::Client,
    config: &HostConfig,
) -> Result<(B256, u64), String> {
    let block_number_hex = format!("0x{:x}", config.block_number);
    let block: BlockResponse = rpc_call(
        client,
        &config.rpc_url,
        "eth_getBlockByNumber",
        json!([block_number_hex, false]),
    )
    .await?;

    let state_root = parse_b256(&block.state_root)?;
    let timestamp = parse_u64(&block.timestamp)?;
    Ok((state_root, timestamp))
}

async fn fetch_proofs(
    client: &reqwest::Client,
    config: &HostConfig,
    slots: &[SlotRequest],
) -> Result<ProofResponse, String> {
    let block_number_hex = format!("0x{:x}", config.block_number);
    let slot_hexes: Vec<String> = slots
        .iter()
        .map(|slot| u256_to_hex_32(slot.slot))
        .collect();

    rpc_call(
        client,
        &config.rpc_url,
        "eth_getProof",
        json!([config.gauge_controller.to_string(), slot_hexes, block_number_hex]),
    )
    .await
}

fn compute_verifier_v2_slots(config: &HostConfig, epoch: u64) -> Vec<SlotRequest> {
    let offset_end = U256::from(2u64);
    let epoch_u256 = U256::from(epoch);

    let last_vote = nested_mapping_slot(
        config.last_vote_mapping_slot,
        encode_address(config.account),
        encode_address(config.gauge),
        U256::ZERO,
    );

    let slope = nested_mapping_slot(
        config.user_slope_mapping_slot,
        encode_address(config.account),
        encode_address(config.gauge),
        U256::ZERO,
    );

    let end = nested_mapping_slot(
        config.user_slope_mapping_slot,
        encode_address(config.account),
        encode_address(config.gauge),
        offset_end,
    );

    let weight = nested_mapping_slot(
        config.weight_mapping_slot,
        encode_address(config.gauge),
        encode_u256(epoch_u256),
        U256::ZERO,
    );

    vec![
        SlotRequest {
            label: "last_vote",
            slot: last_vote,
        },
        SlotRequest {
            label: "user_slope",
            slot: slope,
        },
        SlotRequest {
            label: "user_end",
            slot: end,
        },
        SlotRequest {
            label: "weight_bias",
            slot: weight,
        },
    ]
}

fn nested_mapping_slot(
    slot_number: U256,
    key1: [u8; 32],
    key2: [u8; 32],
    offset: U256,
) -> U256 {
    let outer = keccak256_64(encode_u256(slot_number), key1);
    let inner = keccak256_64(outer, key2);
    U256::from_be_bytes(inner) + offset
}

fn keccak256_64(a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
    let mut input = [0u8; 64];
    input[..32].copy_from_slice(&a);
    input[32..].copy_from_slice(&b);
    keccak256(&input)
}

fn encode_u256(value: U256) -> [u8; 32] {
    value.to_be_bytes::<32>()
}

fn encode_address(address: Address) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[12..].copy_from_slice(address.as_slice());
    out
}

fn u256_to_hex_32(value: U256) -> String {
    format!("0x{}", hex::encode(value.to_be_bytes::<32>()))
}

fn parse_u64(value: &str) -> Result<u64, String> {
    let trimmed = value.strip_prefix("0x").unwrap_or(value);
    let radix = if value.starts_with("0x") { 16 } else { 10 };
    u64::from_str_radix(trimmed, radix).map_err(|err| format!("invalid u64: {err}"))
}

fn parse_b256(value: &str) -> Result<B256, String> {
    let bytes = hex::decode(strip_0x(value)).map_err(|err| format!("invalid hex: {err}"))?;
    if bytes.len() != 32 {
        return Err(format!("expected 32-byte hex, got {}", bytes.len()));
    }
    Ok(B256::from_slice(&bytes))
}

fn strip_0x(value: &str) -> &str {
    value.strip_prefix("0x").unwrap_or(value)
}

fn require_env(name: &str) -> Result<String, String> {
    env::var(name).map_err(|_| format!("missing {name} env var"))
}

fn parse_optional_u64_env(name: &str) -> Option<u64> {
    env::var(name).ok().and_then(|value| parse_u64(&value).ok())
}

fn parse_u64_env(name: &str) -> Result<u64, String> {
    let value = require_env(name)?;
    parse_u64(&value)
}

fn parse_address_env(name: &str) -> Result<Address, String> {
    let value = require_env(name)?;
    Address::from_str(&value).map_err(|err| format!("invalid {name}: {err}"))
}

fn parse_u256_env(name: &str) -> Result<U256, String> {
    let value = require_env(name)?;
    parse_u256(&value).map_err(|err| format!("invalid {name}: {err}"))
}

fn parse_u256(value: &str) -> Result<U256, String> {
    let trimmed = value.strip_prefix("0x").unwrap_or(value);
    let radix = if value.starts_with("0x") { 16 } else { 10 };
    U256::from_str_radix(trimmed, radix).map_err(|err| format!("invalid u256: {err}"))
}

fn decode_proof_nodes(nodes: &[String]) -> Result<Vec<Vec<u8>>, String> {
    nodes
        .iter()
        .map(|node| hex::decode(strip_0x(node)).map_err(|err| format!("invalid proof hex: {err}")))
        .collect()
}

fn build_input(
    state_root: B256,
    gauge_controller: Address,
    slots: &[SlotRequest],
    proof: ProofResponse,
) -> Result<Input, String> {
    if proof.storage_proof.len() != slots.len() {
        return Err(format!(
            "storage proof length mismatch: expected {}, got {}",
            slots.len(),
            proof.storage_proof.len()
        ));
    }

    let account_proof = decode_proof_nodes(&proof.account_proof)?;

    let proofs = slots
        .iter()
        .zip(proof.storage_proof.iter())
        .map(|(slot, storage)| {
            let storage_proof = decode_proof_nodes(&storage.proof)?;
            Ok(StorageProofRequest {
                account: gauge_controller,
                slot: slot.slot,
                account_proof: account_proof.clone(),
                storage_proof,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;

    Ok(Input {
        state_root,
        proofs,
    })
}

#[tokio::main]
async fn main() {
    sp1_sdk::utils::setup_logger();
    dotenvy::dotenv().ok();

    let client = ProverClient::new();
    let mut stdin = SP1Stdin::new();
    let elf = load_elf();

    let config = HostConfig::from_env().expect("Invalid configuration");
    let http_client = reqwest::Client::new();

    let (state_root, timestamp) = fetch_block_state_root(&http_client, &config)
        .await
        .expect("Failed to fetch block state root");
    let epoch = config
        .epoch_override
        .unwrap_or_else(|| (timestamp / ONE_WEEK_SECONDS) * ONE_WEEK_SECONDS);

    let slots = compute_verifier_v2_slots(&config, epoch);
    let proof = fetch_proofs(&http_client, &config, &slots)
        .await
        .expect("Failed to fetch proofs");
    let input = build_input(state_root, config.gauge_controller, &slots, proof)
        .expect("Failed to build input");

    stdin.write(&input);

    println!("VerifierV2 input prepared:");
    println!("Block: {}", config.block_number);
    println!("Epoch: {}", epoch);
    println!("State root: {:?}", input.state_root);
    for slot in &slots {
        println!("Slot {}: 0x{}", slot.label, hex::encode(slot.slot.to_be_bytes::<32>()));
    }

    println!("Executing in mock mode...");
    let (mut public_values, report) = client
        .execute(elf.as_slice(), stdin)
        .run()
        .expect("Execution failed");
    println!("Execution successful!");

    let output = public_values.read::<Output>();
    println!("Cycles: {}", report.total_instruction_count());
    println!("Output State Root: {:?}", output.state_root);
    println!("Verified {} slots", output.results.len());
}
