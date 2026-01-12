use alloy_primitives::{hex, Address, B256, U256};
use rlp::Rlp;
use serde::{Deserialize, Serialize};
use serde_json::json;
use shared::{Input, Output, StorageProofRequest};
use sha3::{Digest, Keccak256};
use sp1_sdk::{ProverClient, SP1Stdin};
use std::{
    collections::HashMap,
    env,
    fs,
    path::{Path, PathBuf},
    process::Command,
    str::FromStr,
};

const DEFAULT_ELF_REL_PATHS: [&str; 3] = [
    "../program/elf/riscv32im-succinct-zkvm-elf",
    "../target/elf-compilation/riscv32im-succinct-zkvm-elf/release/program",
    "../target/elf-compilation/riscv32im-succinct-zkvm-elf/debug/program",
];
const TOOLKIT_ADAPTER: &str = "toolkit_adapter.py";
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

#[derive(Debug, Clone, Copy)]
enum RunMode {
    Execute,
    Prove,
}

impl RunMode {
    fn from_env() -> Self {
        match env::var("RUN_MODE")
            .unwrap_or_else(|_| "execute".to_string())
            .to_lowercase()
            .as_str()
        {
            "prove" => Self::Prove,
            _ => Self::Execute,
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum ProofKind {
    Core,       // Raw SP1 STARK proof; largest, fastest to generate, off-chain only.
    Compressed, // Recursively compressed STARK; smaller, still off-chain.
    Plonk,      // Wrap in BN254 PLONK SNARK; EVM-verifiable, universal setup.
    Groth16,    // Wrap in BN254 Groth16 SNARK; smallest proof, cheapest on-chain.
}

impl ProofKind {
    fn from_env() -> Self {
        match env::var("PROOF_KIND")
            .unwrap_or_else(|_| "core".to_string())
            .to_lowercase()
            .as_str()
        {
            "compressed" => Self::Compressed,
            "plonk" => Self::Plonk,
            "groth16" => Self::Groth16,
            _ => Self::Core,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            ProofKind::Core => "core",
            ProofKind::Compressed => "compressed",
            ProofKind::Plonk => "plonk",
            ProofKind::Groth16 => "groth16",
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum ProofSource {
    Rpc,
    Toolkit,
}

impl ProofSource {
    fn from_env() -> Self {
        match env::var("PROOF_SOURCE")
            .unwrap_or_else(|_| "rpc".to_string())
            .to_lowercase()
            .as_str()
        {
            "toolkit" => Self::Toolkit,
            _ => Self::Rpc,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Protocol {
    Curve,
    Yb,
    Pendle,
    Default,
}

impl Protocol {
    fn from_str(value: &str) -> Self {
        match value.to_lowercase().as_str() {
            "curve" => Self::Curve,
            "yb" => Self::Yb,
            "pendle" => Self::Pendle,
            _ => Self::Default,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
enum RequestKind {
    AccountData,
    PointData,
}

#[derive(Debug, Serialize, Deserialize)]
struct RequestItem {
    #[serde(rename = "type")]
    kind: RequestKind,
    #[serde(default, deserialize_with = "deserialize_optional_address")]
    account: Option<Address>,
    #[serde(default, deserialize_with = "deserialize_optional_address")]
    gauge: Option<Address>,
}

#[derive(Debug, Serialize, Deserialize)]
struct SlotConfig {
    #[serde(deserialize_with = "deserialize_u256")]
    weight_mapping_slot: U256,
    #[serde(deserialize_with = "deserialize_u256")]
    last_vote_mapping_slot: U256,
    #[serde(deserialize_with = "deserialize_u256")]
    user_slope_mapping_slot: U256,
}

#[derive(Debug, Serialize, Deserialize)]
struct HostRequest {
    chain_id: u64,
    block_number: u64,
    #[serde(default)]
    epoch: Option<u64>,
    #[serde(default)]
    protocol: Option<String>,
    #[serde(deserialize_with = "deserialize_address")]
    gauge_controller: Address,
    slots: SlotConfig,
    requests: Vec<RequestItem>,
}

#[derive(Debug)]
struct HostInput {
    chain_id: u64,
    block_number: u64,
    epoch_override: Option<u64>,
    protocol: Protocol,
    protocol_name: String,
    gauge_controller: Address,
    slots: SlotConfig,
    requests: Vec<RequestItem>,
}

impl HostInput {
    fn from_env() -> Result<Self, String> {
        let chain_id = parse_optional_u64_env("CHAIN_ID").unwrap_or(1);
        let block_number = parse_u64_env("BLOCK_NUMBER")?;
        let protocol_name = env::var("PROTOCOL")
            .unwrap_or_else(|_| "curve".to_string())
            .to_lowercase();
        let protocol = Protocol::from_str(&protocol_name);
        let gauge_controller = parse_address_env("GAUGE_CONTROLLER")?;
        let gauge = parse_address_env("GAUGE")?;
        let account = parse_address_env("ACCOUNT")?;
        let weight_mapping_slot = parse_u256_env("WEIGHT_MAPPING_SLOT")?;
        let last_vote_mapping_slot = parse_u256_env("LAST_VOTE_MAPPING_SLOT")?;
        let user_slope_mapping_slot = parse_u256_env("USER_SLOPE_MAPPING_SLOT")?;
        let epoch_override = parse_optional_u64_env("EPOCH");

        Ok(Self {
            chain_id,
            block_number,
            epoch_override,
            protocol,
            protocol_name,
            gauge_controller,
            slots: SlotConfig {
                weight_mapping_slot,
                last_vote_mapping_slot,
                user_slope_mapping_slot,
            },
            requests: vec![
                RequestItem {
                    kind: RequestKind::AccountData,
                    account: Some(account),
                    gauge: Some(gauge),
                },
                RequestItem {
                    kind: RequestKind::PointData,
                    account: None,
                    gauge: Some(gauge),
                },
            ],
        })
    }

    fn from_request(request: HostRequest) -> Self {
        let protocol_name = request
            .protocol
            .unwrap_or_else(|| "curve".to_string())
            .to_lowercase();
        Self {
            chain_id: request.chain_id,
            block_number: request.block_number,
            epoch_override: request.epoch,
            protocol: Protocol::from_str(&protocol_name),
            protocol_name,
            gauge_controller: request.gauge_controller,
            slots: request.slots,
            requests: request.requests,
        }
    }

    fn load() -> Result<Self, String> {
        if let Ok(path) = env::var("INPUT_JSON") {
            let contents = fs::read_to_string(&path)
                .map_err(|err| format!("failed to read INPUT_JSON {}: {err}", path))?;
            let request: HostRequest =
                serde_json::from_str(&contents).map_err(|err| format!("invalid INPUT_JSON: {err}"))?;
            Ok(Self::from_request(request))
        } else {
            Self::from_env()
        }
    }

    fn to_json_value(&self, epoch: u64) -> serde_json::Value {
        let requests: Vec<serde_json::Value> = self
            .requests
            .iter()
            .map(|request| {
                let kind = match request.kind {
                    RequestKind::AccountData => "account_data",
                    RequestKind::PointData => "point_data",
                };
                json!({
                    "type": kind,
                    "account": request.account.map(|address| address.to_string()),
                    "gauge": request.gauge.map(|address| address.to_string()),
                })
            })
            .collect();

        json!({
            "chain_id": self.chain_id,
            "block_number": self.block_number,
            "epoch": epoch,
            "protocol": self.protocol_name.as_str(),
            "gauge_controller": self.gauge_controller.to_string(),
            "slots": {
                "weight_mapping_slot": u256_to_hex(self.slots.weight_mapping_slot),
                "last_vote_mapping_slot": u256_to_hex(self.slots.last_vote_mapping_slot),
                "user_slope_mapping_slot": u256_to_hex(self.slots.user_slope_mapping_slot),
            },
            "requests": requests,
        })
    }
}

#[derive(Debug, Clone)]
struct SlotRequest {
    label: String,
    slot: U256,
}

#[derive(Debug)]
struct RequestSlots {
    kind: RequestKind,
    account: Option<Address>,
    gauge: Address,
    slots: Vec<SlotRequest>,
}

#[derive(Serialize)]
struct ProofArtifact {
    proof_kind: String,
    proof_bytes: Option<String>,
    public_values_raw: String,
    public_values_hash: String,
    public_values_hash_bn254: String,
    output: Output,
}

#[derive(Debug, Deserialize)]
struct ToolkitGaugeProof {
    #[serde(deserialize_with = "deserialize_address")]
    gauge: Address,
    #[serde(rename = "gauge_controller_proof")]
    gauge_controller_proof: String,
    #[serde(rename = "point_data_proof")]
    point_data_proof: String,
}

#[derive(Debug, Deserialize)]
struct ToolkitUserProof {
    #[serde(deserialize_with = "deserialize_address")]
    account: Address,
    #[serde(deserialize_with = "deserialize_address")]
    gauge: Address,
    #[serde(rename = "account_proof")]
    account_proof: String,
    #[serde(rename = "storage_proof")]
    storage_proof: String,
}

#[derive(Debug, Deserialize)]
struct ToolkitProofBundle {
    #[serde(default)]
    protocol: Option<String>,
    #[serde(default)]
    block_number: Option<u64>,
    #[serde(default)]
    epoch: Option<u64>,
    #[serde(default)]
    gauge_proofs: Vec<ToolkitGaugeProof>,
    #[serde(default)]
    user_proofs: Vec<ToolkitUserProof>,
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
    rpc_url: &str,
    block_number: u64,
) -> Result<(B256, u64), String> {
    let block_number_hex = format!("0x{:x}", block_number);
    let block: BlockResponse = rpc_call(
        client,
        rpc_url,
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
    rpc_url: &str,
    gauge_controller: Address,
    block_number: u64,
    slots: &[SlotRequest],
) -> Result<ProofResponse, String> {
    let block_number_hex = format!("0x{:x}", block_number);
    let slot_hexes: Vec<String> = slots.iter().map(|slot| u256_to_hex_32(slot.slot)).collect();

    rpc_call(
        client,
        rpc_url,
        "eth_getProof",
        json!([gauge_controller.to_string(), slot_hexes, block_number_hex]),
    )
    .await
}

fn expand_requests(input: &HostInput, epoch: u64) -> Result<Vec<RequestSlots>, String> {
    let mut expanded = Vec::new();

    for request in &input.requests {
        let gauge = request
            .gauge
            .ok_or_else(|| "request missing gauge".to_string())?;
        let account = request.account;
        let mut slots = Vec::new();

        match request.kind {
            RequestKind::PointData => {
                let slot = gauge_time_slot(input.protocol, gauge, epoch, input.slots.weight_mapping_slot);
                slots.push(SlotRequest {
                    label: "weight_bias".to_string(),
                    slot,
                });
            }
            RequestKind::AccountData => {
                if account.is_none() {
                    return Err("account_data request missing account".to_string());
                }

                slots.extend(user_vote_slots(
                    input.protocol,
                    account.unwrap(),
                    gauge,
                    input.slots.last_vote_mapping_slot,
                    input.slots.user_slope_mapping_slot,
                ));
            }
        }

        expanded.push(RequestSlots {
            kind: request.kind.clone(),
            account,
            gauge,
            slots,
        });
    }

    Ok(expanded)
}

fn gauge_time_slot(protocol: Protocol, gauge: Address, epoch: u64, base_slot: U256) -> U256 {
    match protocol {
        Protocol::Curve => gauge_time_slot_pre_vyper03(gauge, epoch, base_slot),
        Protocol::Yb => gauge_time_slot_yb(gauge, base_slot),
        Protocol::Pendle => gauge_time_slot_pendle(gauge, epoch, base_slot),
        Protocol::Default => gauge_time_slot_default(gauge, epoch, base_slot),
    }
}

fn user_vote_slots(
    protocol: Protocol,
    account: Address,
    gauge: Address,
    last_vote_base_slot: U256,
    user_slope_base_slot: U256,
) -> Vec<SlotRequest> {
    let mut slots = Vec::new();

    if protocol != Protocol::Pendle {
        let last_vote_slot = match protocol {
            Protocol::Curve => user_gauge_slot_pre_vyper03(account, gauge, last_vote_base_slot),
            Protocol::Yb => user_gauge_slot_default(account, gauge, last_vote_base_slot),
            Protocol::Default => user_gauge_slot_default(account, gauge, last_vote_base_slot),
            Protocol::Pendle => unreachable!(),
        };
        slots.push(SlotRequest {
            label: "last_vote".to_string(),
            slot: last_vote_slot,
        });
    }

    let vote_user_slope_slot = match protocol {
        Protocol::Curve => user_gauge_slot_pre_vyper03(account, gauge, user_slope_base_slot),
        Protocol::Yb => user_gauge_slot_default(account, gauge, user_slope_base_slot),
        Protocol::Pendle => user_gauge_slot_pendle(account, gauge, user_slope_base_slot),
        Protocol::Default => user_gauge_slot_default(account, gauge, user_slope_base_slot),
    };

    slots.push(SlotRequest {
        label: "user_slope".to_string(),
        slot: vote_user_slope_slot,
    });

    let additional_offsets: Vec<(u64, &str)> = match protocol {
        Protocol::Yb => vec![(1, "user_bias"), (3, "user_end")],
        Protocol::Pendle => vec![(1, "user_bias")],
        _ => vec![(2, "user_end")],
    };

    for (offset, label) in additional_offsets {
        slots.push(SlotRequest {
            label: label.to_string(),
            slot: vote_user_slope_slot + U256::from(offset),
        });
    }

    slots
}

fn gauge_time_slot_default(gauge: Address, epoch: u64, base_slot: U256) -> U256 {
    let gauge_encoded = keccak_abi_encode(&[encode_u256(base_slot), encode_address(gauge)]);
    let inner = keccak_abi_encode(&[gauge_encoded, encode_u256(U256::from(epoch))]);
    U256::from_be_bytes(inner)
}

fn gauge_time_slot_pre_vyper03(gauge: Address, epoch: u64, base_slot: U256) -> U256 {
    let gauge_encoded = keccak_abi_encode(&[encode_u256(base_slot), encode_address(gauge)]);
    let inner = keccak_abi_encode(&[gauge_encoded, encode_u256(U256::from(epoch))]);
    let final_hash = keccak_abi_encode(&[inner]);
    U256::from_be_bytes(final_hash)
}

fn gauge_time_slot_yb(gauge: Address, base_slot: U256) -> U256 {
    let gauge_encoded = keccak_abi_encode(&[encode_u256(base_slot), encode_address(gauge)]);
    U256::from_be_bytes(gauge_encoded)
}

fn gauge_time_slot_pendle(gauge: Address, epoch: u64, base_slot: U256) -> U256 {
    let encoded_1 = keccak_abi_encode(&[
        encode_uint128(epoch as u128),
        encode_u256(base_slot),
    ]);
    let struct_slot = U256::from_be_bytes(encoded_1) + U256::from(1u64);
    let encoded_2 = keccak_abi_encode(&[encode_address(gauge), encode_u256(struct_slot)]);
    U256::from_be_bytes(encoded_2)
}

fn user_gauge_slot_default(account: Address, gauge: Address, base_slot: U256) -> U256 {
    let user_encoded = keccak_abi_encode(&[encode_u256(base_slot), encode_address(account)]);
    let final_hash = keccak_abi_encode(&[user_encoded, encode_address(gauge)]);
    U256::from_be_bytes(final_hash)
}

fn user_gauge_slot_pre_vyper03(account: Address, gauge: Address, base_slot: U256) -> U256 {
    let user_encoded = keccak_abi_encode(&[encode_u256(base_slot), encode_address(account)]);
    let intermediate = keccak_abi_encode(&[user_encoded, encode_address(gauge)]);
    let final_hash = keccak_abi_encode(&[intermediate]);
    U256::from_be_bytes(final_hash)
}

fn user_gauge_slot_pendle(account: Address, gauge: Address, base_slot: U256) -> U256 {
    let encoded_1 = keccak_abi_encode(&[encode_address(account), encode_u256(base_slot)]);
    let struct_slot = U256::from_be_bytes(encoded_1) + U256::from(1u64);
    let encoded_2 = keccak_abi_encode(&[encode_address(gauge), encode_u256(struct_slot)]);
    U256::from_be_bytes(encoded_2)
}

fn keccak_abi_encode(words: &[[u8; 32]]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(words.len() * 32);
    for word in words {
        buf.extend_from_slice(word);
    }
    keccak256(&buf)
}

fn encode_u256(value: U256) -> [u8; 32] {
    value.to_be_bytes::<32>()
}

fn encode_uint128(value: u128) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[16..].copy_from_slice(&value.to_be_bytes());
    out
}

fn encode_address(address: Address) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[12..].copy_from_slice(address.as_slice());
    out
}

fn u256_to_hex_32(value: U256) -> String {
    format!("0x{}", hex::encode(value.to_be_bytes::<32>()))
}

fn u256_to_hex(value: U256) -> String {
    format!("0x{:x}", value)
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

fn parse_optional_bool_env(name: &str) -> Option<bool> {
    env::var(name).ok().map(|value| {
        matches!(value.to_lowercase().as_str(), "1" | "true" | "yes")
    })
}

fn toolkit_rpc_env_name(chain_id: u64) -> Result<&'static str, String> {
    match chain_id {
        1 => Ok("ETHEREUM_MAINNET_RPC_URL"),
        10 => Ok("OPTIMISM_MAINNET_RPC_URL"),
        42161 => Ok("ARBITRUM_MAINNET_RPC_URL"),
        8453 => Ok("BASE_MAINNET_RPC_URL"),
        137 => Ok("POLYGON_MAINNET_RPC_URL"),
        56 => Ok("BSC_MAINNET_RPC_URL"),
        _ => Err(format!("unsupported chain id {chain_id}")),
    }
}

fn resolve_rpc_url(chain_id: u64) -> Result<(String, &'static str), String> {
    let env_name = toolkit_rpc_env_name(chain_id)?;

    if let Ok(rpc_url) = env::var(env_name) {
        return Ok((rpc_url, env_name));
    }

    Err(format!("missing RPC_URL or {env_name}"))
}

fn resolve_python_bin() -> String {
    if let Ok(python) = env::var("PYTHON_BIN") {
        return python;
    }

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().map(PathBuf::from);
    let root = root.unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf());
    let candidates = [
        root.join(".venv/bin/python"),
        root.join(".venv/bin/python3"),
        root.join(".venv/Scripts/python.exe"),
    ];

    for candidate in candidates {
        if candidate.exists() {
            return candidate.to_string_lossy().to_string();
        }
    }

    "python3".to_string()
}

fn decode_proof_nodes(nodes: &[String]) -> Result<Vec<Vec<u8>>, String> {
    nodes
        .iter()
        .map(|node| hex::decode(strip_0x(node)).map_err(|err| format!("invalid proof hex: {err}")))
        .collect()
}

fn decode_hex_bytes(value: &str) -> Result<Vec<u8>, String> {
    hex::decode(strip_0x(value)).map_err(|err| format!("invalid hex: {err}"))
}

fn decode_rlp_node_list(value: &str) -> Result<Vec<Vec<u8>>, String> {
    let bytes = decode_hex_bytes(value)?;
    let rlp = Rlp::new(&bytes);
    if !rlp.is_list() {
        return Err("expected RLP list for node list".to_string());
    }
    let count = rlp.item_count().map_err(|err| format!("rlp count failed: {err}"))?;
    let mut nodes = Vec::with_capacity(count);
    for idx in 0..count {
        let item = rlp.at(idx).map_err(|err| format!("rlp node failed: {err}"))?;
        nodes.push(item.as_raw().to_vec());
    }
    Ok(nodes)
}

fn decode_rlp_proof_list(value: &str) -> Result<Vec<Vec<Vec<u8>>>, String> {
    let bytes = decode_hex_bytes(value)?;
    let rlp = Rlp::new(&bytes);
    if !rlp.is_list() {
        return Err("expected RLP list for proof list".to_string());
    }
    let count = rlp.item_count().map_err(|err| format!("rlp count failed: {err}"))?;
    let mut proofs = Vec::with_capacity(count);
    for idx in 0..count {
        let proof_item = rlp.at(idx).map_err(|err| format!("rlp proof failed: {err}"))?;
        if !proof_item.is_list() {
            return Err("expected proof item list".to_string());
        }
        let node_count = proof_item
            .item_count()
            .map_err(|err| format!("rlp node count failed: {err}"))?;
        let mut nodes = Vec::with_capacity(node_count);
        for node_idx in 0..node_count {
            let node = proof_item
                .at(node_idx)
                .map_err(|err| format!("rlp node failed: {err}"))?;
            nodes.push(node.as_raw().to_vec());
        }
        proofs.push(nodes);
    }
    Ok(proofs)
}

fn build_input_from_rpc(
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

fn build_input_from_toolkit(
    state_root: B256,
    gauge_controller: Address,
    requests: &[RequestSlots],
    bundle: ToolkitProofBundle,
) -> Result<Input, String> {
    let mut gauge_proofs = HashMap::new();
    for proof in bundle.gauge_proofs {
        gauge_proofs.insert(proof.gauge, proof);
    }

    let mut user_proofs = HashMap::new();
    for proof in bundle.user_proofs {
        user_proofs.insert((proof.account, proof.gauge), proof);
    }

    let mut account_proof_nodes: Option<Vec<Vec<u8>>> = None;
    if let Some(proof) = gauge_proofs.values().next() {
        account_proof_nodes = Some(decode_rlp_node_list(&proof.gauge_controller_proof)?);
    } else if let Some(proof) = user_proofs.values().next() {
        account_proof_nodes = Some(decode_rlp_node_list(&proof.account_proof)?);
    }

    let account_proof_nodes = account_proof_nodes.ok_or_else(|| "missing account proof".to_string())?;

    let mut storage_requests = Vec::new();

    for request in requests {
        match request.kind {
            RequestKind::PointData => {
                let proof = gauge_proofs
                    .get(&request.gauge)
                    .ok_or_else(|| "missing gauge proof".to_string())?;
                let proofs = decode_rlp_proof_list(&proof.point_data_proof)?;
                if proofs.len() != request.slots.len() {
                    return Err(format!(
                        "gauge proof length mismatch: expected {}, got {}",
                        request.slots.len(),
                        proofs.len()
                    ));
                }
                for (slot, storage_proof) in request.slots.iter().zip(proofs.into_iter()) {
                    storage_requests.push(StorageProofRequest {
                        account: gauge_controller,
                        slot: slot.slot,
                        account_proof: account_proof_nodes.clone(),
                        storage_proof,
                    });
                }
            }
            RequestKind::AccountData => {
                let key = (request.account.ok_or_else(|| "missing account".to_string())?, request.gauge);
                let proof = user_proofs
                    .get(&key)
                    .ok_or_else(|| "missing user proof".to_string())?;
                let proofs = decode_rlp_proof_list(&proof.storage_proof)?;
                if proofs.len() != request.slots.len() {
                    return Err(format!(
                        "user proof length mismatch: expected {}, got {}",
                        request.slots.len(),
                        proofs.len()
                    ));
                }
                for (slot, storage_proof) in request.slots.iter().zip(proofs.into_iter()) {
                    storage_requests.push(StorageProofRequest {
                        account: gauge_controller,
                        slot: slot.slot,
                        account_proof: account_proof_nodes.clone(),
                        storage_proof,
                    });
                }
            }
        }
    }

    Ok(Input {
        state_root,
        proofs: storage_requests,
    })
}

fn ensure_input_json(input: &HostInput, epoch: u64) -> Result<PathBuf, String> {
    if let Ok(path) = env::var("INPUT_JSON") {
        return Ok(PathBuf::from(path));
    }

    let output_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("output");
    fs::create_dir_all(&output_dir)
        .map_err(|err| format!("failed to create output dir: {err}"))?;
    let path = output_dir.join("host_input.json");
    let payload = serde_json::to_string_pretty(&input.to_json_value(epoch))
        .map_err(|err| format!("failed to serialize host input: {err}"))?;
    fs::write(&path, payload).map_err(|err| format!("failed to write host input: {err}"))?;
    Ok(path)
}

fn run_toolkit(
    input_path: &Path,
    rpc_env_name: &str,
    rpc_url: &str,
) -> Result<ToolkitProofBundle, String> {
    let toolkit_root = env::var("TOOLKIT_ROOT").ok().map(PathBuf::from);
    let adapter = Path::new(env!("CARGO_MANIFEST_DIR")).join(TOOLKIT_ADAPTER);

    let mut command = Command::new(resolve_python_bin());
    command.arg(adapter).arg(input_path);
    command.env(rpc_env_name, rpc_url);
    if let Some(toolkit_root) = toolkit_root {
        command.env("PYTHONPATH", toolkit_root);
    }

    let output = command
        .output()
        .map_err(|err| format!("toolkit execution failed: {err}"))?;

    if !output.status.success() {
        return Err(format!(
            "toolkit exited with status {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    serde_json::from_slice(&output.stdout)
        .map_err(|err| format!("failed to parse toolkit output: {err}"))
}

fn persist_proof(
    proof_kind: ProofKind,
    proof: &sp1_sdk::SP1ProofWithPublicValues,
    output: Output,
) -> Result<(), String> {
    let output_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("output");
    fs::create_dir_all(&output_dir)
        .map_err(|err| format!("failed to create output dir: {err}"))?;

    let proof_path = env::var("PROOF_OUTPUT").unwrap_or_else(|_| "proof.bin".to_string());
    let proof_path = PathBuf::from(proof_path);
    let proof_path = if proof_path.is_relative() {
        output_dir.join(proof_path)
    } else {
        proof_path
    };

    proof
        .save(&proof_path)
        .map_err(|err| format!("failed to save proof: {err}"))?;

    let proof_json_path = env::var("PROOF_JSON").unwrap_or_else(|_| "proof.json".to_string());
    let proof_json_path = PathBuf::from(proof_json_path);
    let proof_json_path = if proof_json_path.is_relative() {
        output_dir.join(proof_json_path)
    } else {
        proof_json_path
    };

    let proof_bytes = match proof_kind {
        ProofKind::Plonk | ProofKind::Groth16 => Some(format!("0x{}", hex::encode(proof.bytes()))),
        _ => None,
    };

    let public_values_raw = proof.public_values.raw();
    let public_values_hash = format!("0x{}", hex::encode(proof.public_values.hash()));
    let public_values_hash_bn254 = format!(
        "0x{}",
        proof.public_values.hash_bn254().to_str_radix(16)
    );

    let artifact = ProofArtifact {
        proof_kind: proof_kind.as_str().to_string(),
        proof_bytes,
        public_values_raw,
        public_values_hash,
        public_values_hash_bn254,
        output,
    };

    let json_bytes = serde_json::to_vec_pretty(&artifact)
        .map_err(|err| format!("failed to serialize proof artifact: {err}"))?;
    fs::write(&proof_json_path, json_bytes)
        .map_err(|err| format!("failed to write proof artifact: {err}"))?;

    println!("Proof saved to {}", proof_path.display());
    println!("Proof artifact saved to {}", proof_json_path.display());
    Ok(())
}

#[tokio::main]
async fn main() {
    sp1_sdk::utils::setup_logger();
    dotenvy::dotenv().ok();

    let run_mode = RunMode::from_env();
    let proof_kind = ProofKind::from_env();
    let proof_source = ProofSource::from_env();
    let verify_proof = parse_optional_bool_env("VERIFY_PROOF").unwrap_or(false);

    let host_input = HostInput::load().expect("Invalid host input");
    let (rpc_url, rpc_env_name) =
        resolve_rpc_url(host_input.chain_id).expect("Missing RPC_URL or chain RPC env");

    let client = ProverClient::new();
    let mut stdin = SP1Stdin::new();
    let elf = load_elf();

    let http_client = reqwest::Client::new();

    let (state_root, timestamp) =
        fetch_block_state_root(&http_client, &rpc_url, host_input.block_number)
            .await
            .expect("Failed to fetch block state root");

    let epoch = host_input
        .epoch_override
        .unwrap_or_else(|| (timestamp / ONE_WEEK_SECONDS) * ONE_WEEK_SECONDS);

    let requests = expand_requests(&host_input, epoch).expect("Failed to expand requests");
    let mut flat_slots = Vec::new();
    for request in &requests {
        for slot in &request.slots {
            flat_slots.push(slot.clone());
        }
    }

    let input = match proof_source {
        ProofSource::Rpc => {
            let proof = fetch_proofs(
                &http_client,
                &rpc_url,
                host_input.gauge_controller,
                host_input.block_number,
                &flat_slots,
            )
            .await
            .expect("Failed to fetch proofs");
            build_input_from_rpc(state_root, host_input.gauge_controller, &flat_slots, proof)
                .expect("Failed to build input")
        }
        ProofSource::Toolkit => {
            let input_path = ensure_input_json(&host_input, epoch).expect("Failed to create input JSON");
            let bundle = run_toolkit(&input_path, rpc_env_name, &rpc_url).expect("Failed to run toolkit");
            build_input_from_toolkit(state_root, host_input.gauge_controller, &requests, bundle)
                .expect("Failed to build toolkit input")
        }
    };

    stdin.write(&input);

    println!("Input prepared:");
    println!("Block: {}", host_input.block_number);
    println!("Epoch: {}", epoch);
    println!("State root: {:?}", input.state_root);
    for request in &requests {
        let label = match request.kind {
            RequestKind::AccountData => "account_data",
            RequestKind::PointData => "point_data",
        };
        println!("Request {} gauge={} account={:?}", label, request.gauge, request.account);
        for slot in &request.slots {
            println!("  Slot {}: 0x{}", slot.label, hex::encode(slot.slot.to_be_bytes::<32>()));
        }
    }

    match run_mode {
        RunMode::Execute => {
            println!("Executing in mock mode...");
            let (public_values, report) = client
                .execute(elf.as_slice(), stdin)
                .run()
                .expect("Execution failed");
            println!("Execution successful!");

            let mut public_values_clone = public_values.clone();
            let output = public_values_clone.read::<Output>();

            println!("Cycles: {}", report.total_instruction_count());
            println!("Output State Root: {:?}", output.state_root);
            println!("Verified {} slots", output.results.len());
        }
        RunMode::Prove => {
            println!("Generating proof (mode: {})...", proof_kind.as_str());
            let (pk, vk) = client.setup(elf.as_slice());

            let proof = match proof_kind {
                ProofKind::Core => client.prove(&pk, stdin).run(),
                ProofKind::Compressed => client.prove(&pk, stdin).compressed().run(),
                ProofKind::Plonk => client.prove(&pk, stdin).plonk().run(),
                ProofKind::Groth16 => client.prove(&pk, stdin).groth16().run(),
            }
            .expect("Proof generation failed");

            if verify_proof {
                client.verify(&proof, &vk).expect("Proof verification failed");
                println!("Proof verification succeeded");
            }

            let mut public_values_clone = proof.public_values.clone();
            let output = public_values_clone.read::<Output>();

            println!("Proof generated!");
            println!("Output State Root: {:?}", output.state_root);
            println!("Verified {} slots", output.results.len());

            persist_proof(proof_kind, &proof, output).expect("Failed to persist proof");
        }
    }
}

fn deserialize_address<'de, D>(deserializer: D) -> Result<Address, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    Address::from_str(&value).map_err(serde::de::Error::custom)
}

fn deserialize_optional_address<'de, D>(deserializer: D) -> Result<Option<Address>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<String>::deserialize(deserializer)?;
    match value {
        Some(value) => Ok(Some(
            Address::from_str(&value).map_err(serde::de::Error::custom)?,
        )),
        None => Ok(None),
    }
}

fn deserialize_u256<'de, D>(deserializer: D) -> Result<U256, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    parse_u256(&value).map_err(serde::de::Error::custom)
}
