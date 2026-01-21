//! Encoding, parsing, and serde helper utilities.

use alloy_primitives::{hex, Address, B256, U256};
use alloy_sol_types::{sol, SolValue};
use rlp::Rlp;
use serde::Deserialize;
use sha3::{Digest, Keccak256};
use shared::{AccountResult as SharedAccountResult, Output, PointResult as SharedPointResult};
use std::{env, str::FromStr};

// Solidity-compatible types for ABI decoding.
// These must match the types defined in the SP1 circuit's main.rs
sol! {
    struct PointResult {
        address gauge;
        uint256 epoch;
        uint256 bias;
    }

    struct AccountResult {
        address account;
        address gauge;
        uint256 epoch;
        uint256 slope;
        uint256 end;
        uint256 lastVote;
    }

    /// Public values struct committed by the circuit.
    struct PublicValues {
        bytes32 stateRoot;
        uint256 epoch;
        PointResult[] pointResults;
        AccountResult[] accountResults;
    }
}

///////////////////////////////////////////////
// HASHING
///////////////////////////////////////////////

pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn keccak_abi_encode(words: &[[u8; 32]]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(words.len() * 32);
    for word in words {
        buf.extend_from_slice(word);
    }
    keccak256(&buf)
}

///////////////////////////////////////////////
// ABI ENCODING
///////////////////////////////////////////////

pub fn encode_u256(value: U256) -> [u8; 32] {
    value.to_be_bytes::<32>()
}

pub fn encode_uint128(value: u128) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[16..].copy_from_slice(&value.to_be_bytes());
    out
}

pub fn encode_address(address: Address) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[12..].copy_from_slice(address.as_slice());
    out
}

///////////////////////////////////////////////
// HEX FORMATTING
///////////////////////////////////////////////

pub fn u256_to_hex_32(value: U256) -> String {
    format!("0x{}", hex::encode(value.to_be_bytes::<32>()))
}

pub fn u256_to_hex(value: U256) -> String {
    format!("0x{value:x}")
}

///////////////////////////////////////////////
// PARSING
///////////////////////////////////////////////

pub fn strip_0x(value: &str) -> &str {
    value.strip_prefix("0x").unwrap_or(value)
}

pub fn parse_u64(value: &str) -> Result<u64, String> {
    let trimmed = value.strip_prefix("0x").unwrap_or(value);
    let radix = if value.starts_with("0x") { 16 } else { 10 };
    u64::from_str_radix(trimmed, radix).map_err(|err| format!("invalid u64: {err}"))
}

pub fn parse_b256(value: &str) -> Result<B256, String> {
    let bytes = hex::decode(strip_0x(value)).map_err(|err| format!("invalid hex: {err}"))?;
    if bytes.len() != 32 {
        return Err(format!("expected 32-byte hex, got {}", bytes.len()));
    }
    Ok(B256::from_slice(&bytes))
}

pub fn parse_u256(value: &str) -> Result<U256, String> {
    let trimmed = value.strip_prefix("0x").unwrap_or(value);
    let radix = if value.starts_with("0x") { 16 } else { 10 };
    U256::from_str_radix(trimmed, radix).map_err(|err| format!("invalid u256: {err}"))
}

///////////////////////////////////////////////
// ENVIRONMENT VARIABLE HELPERS
///////////////////////////////////////////////

pub fn require_env(name: &str) -> Result<String, String> {
    env::var(name).map_err(|_| format!("missing {name} env var"))
}

pub fn parse_optional_u64_env(name: &str) -> Option<u64> {
    env::var(name).ok().and_then(|value| parse_u64(&value).ok())
}

pub fn parse_address_env(name: &str) -> Result<Address, String> {
    let value = require_env(name)?;
    Address::from_str(&value).map_err(|err| format!("invalid {name}: {err}"))
}

pub fn parse_optional_address_env(name: &str) -> Option<Address> {
    env::var(name)
        .ok()
        .and_then(|value| Address::from_str(&value).ok())
}

pub fn parse_optional_u256_env(name: &str) -> Option<U256> {
    env::var(name).ok().and_then(|value| parse_u256(&value).ok())
}

pub fn parse_optional_bool_env(name: &str) -> Option<bool> {
    env::var(name)
        .ok()
        .map(|value| matches!(value.to_lowercase().as_str(), "1" | "true" | "yes"))
}

///////////////////////////////////////////////
// RPC URL RESOLUTION
///////////////////////////////////////////////

pub fn toolkit_rpc_env_name(chain_id: u64) -> Result<&'static str, String> {
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

pub fn resolve_rpc_url(chain_id: u64) -> Result<(String, &'static str), String> {
    let env_name = toolkit_rpc_env_name(chain_id)?;

    if let Ok(rpc_url) = env::var(env_name) {
        return Ok((rpc_url, env_name));
    }

    Err(format!("missing RPC_URL or {env_name}"))
}

///////////////////////////////////////////////
// PROOF DECODING (RLP)
///////////////////////////////////////////////

pub fn decode_proof_nodes(nodes: &[String]) -> Result<Vec<Vec<u8>>, String> {
    nodes
        .iter()
        .map(|node| hex::decode(strip_0x(node)).map_err(|err| format!("invalid proof hex: {err}")))
        .collect()
}

pub fn decode_hex_bytes(value: &str) -> Result<Vec<u8>, String> {
    hex::decode(strip_0x(value)).map_err(|err| format!("invalid hex: {err}"))
}

pub fn decode_rlp_node_list(value: &str) -> Result<Vec<Vec<u8>>, String> {
    let bytes = decode_hex_bytes(value)?;
    let rlp = Rlp::new(&bytes);
    if !rlp.is_list() {
        return Err("expected RLP list for node list".to_string());
    }
    let count = rlp
        .item_count()
        .map_err(|err| format!("rlp count failed: {err}"))?;
    let mut nodes = Vec::with_capacity(count);
    for idx in 0..count {
        let item = rlp
            .at(idx)
            .map_err(|err| format!("rlp node failed: {err}"))?;
        nodes.push(item.as_raw().to_vec());
    }
    Ok(nodes)
}

pub fn decode_rlp_proof_list(value: &str) -> Result<Vec<Vec<Vec<u8>>>, String> {
    let bytes = decode_hex_bytes(value)?;
    let rlp = Rlp::new(&bytes);
    if !rlp.is_list() {
        return Err("expected RLP list for proof list".to_string());
    }
    let count = rlp
        .item_count()
        .map_err(|err| format!("rlp count failed: {err}"))?;
    let mut proofs = Vec::with_capacity(count);
    for idx in 0..count {
        let proof_item = rlp
            .at(idx)
            .map_err(|err| format!("rlp proof failed: {err}"))?;
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

///////////////////////////////////////////////
// SERDE HELPERS
///////////////////////////////////////////////

pub fn deserialize_address<'de, D>(deserializer: D) -> Result<Address, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    Address::from_str(&value).map_err(serde::de::Error::custom)
}

pub fn deserialize_optional_address<'de, D>(deserializer: D) -> Result<Option<Address>, D::Error>
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

pub fn deserialize_u256<'de, D>(deserializer: D) -> Result<U256, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    parse_u256(&value).map_err(serde::de::Error::custom)
}

///////////////////////////////////////////////
// ABI DECODING (Public Values)
///////////////////////////////////////////////

/// Decode ABI-encoded public values from the SP1 circuit into an Output struct.
///
/// The circuit uses `PublicValues::abi_encode() + commit_slice()` to output data
/// following SP1's recommended pattern from the project template.
///
/// Expected format: PublicValues struct (stateRoot, epoch, pointResults[], accountResults[])
pub fn decode_abi_public_values(raw_bytes: &[u8]) -> Result<Output, String> {
    let decoded = PublicValues::abi_decode(raw_bytes, true)
        .map_err(|err| format!("ABI decode failed: {err}"))?;

    // Convert epoch from U256 to u64
    let epoch: u64 = decoded
        .epoch
        .try_into()
        .map_err(|_| "epoch overflow: value exceeds u64 max")?;

    // Convert Solidity types to shared Output types
    let point_results: Vec<SharedPointResult> = decoded
        .pointResults
        .into_iter()
        .map(|p| {
            let epoch_val: u64 = p.epoch.try_into().expect("point epoch overflow");
            SharedPointResult {
                gauge: p.gauge,
                epoch: epoch_val,
                bias: p.bias,
            }
        })
        .collect();

    let account_results: Vec<SharedAccountResult> = decoded
        .accountResults
        .into_iter()
        .map(|a| {
            let epoch_val: u64 = a.epoch.try_into().expect("account epoch overflow");
            SharedAccountResult {
                account: a.account,
                gauge: a.gauge,
                epoch: epoch_val,
                slope: a.slope,
                end: a.end,
                last_vote: a.lastVote,
            }
        })
        .collect();

    Ok(Output {
        state_root: decoded.stateRoot,
        epoch,
        point_results,
        account_results,
    })
}
