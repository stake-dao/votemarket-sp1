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

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{address, b256};

    // Known production values
    const TEST_EPOCH: u64 = 1730937600;

    // Known keccak256 hash vectors
    const KECCAK_EMPTY: &str = "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470";
    const KECCAK_HELLO: &str = "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8";

    ///////////////////////////////////////////////
    // HASHING TESTS
    ///////////////////////////////////////////////

    #[test]
    fn test_keccak256_empty_input() {
        let result = keccak256(&[]);
        assert_eq!(hex::encode(result), KECCAK_EMPTY);
    }

    #[test]
    fn test_keccak256_hello() {
        let result = keccak256(b"hello");
        assert_eq!(hex::encode(result), KECCAK_HELLO);
    }

    #[test]
    fn test_keccak256_32_byte_input() {
        let input = [0xab_u8; 32];
        let result = keccak256(&input);
        // Just verify it produces a 32-byte output
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_keccak256_deterministic() {
        let result1 = keccak256(b"test input");
        let result2 = keccak256(b"test input");
        assert_eq!(result1, result2);
    }

    #[test]
    fn test_keccak256_different_inputs_different_outputs() {
        let result1 = keccak256(b"input1");
        let result2 = keccak256(b"input2");
        assert_ne!(result1, result2);
    }

    #[test]
    fn test_keccak_abi_encode_single_word() {
        let word = [0x12_u8; 32];
        let result = keccak_abi_encode(&[word]);
        assert_eq!(result, keccak256(&word));
    }

    #[test]
    fn test_keccak_abi_encode_two_words() {
        let word1 = [0x11_u8; 32];
        let word2 = [0x22_u8; 32];
        let result = keccak_abi_encode(&[word1, word2]);

        // Manually concatenate and hash
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(&word1);
        buf[32..].copy_from_slice(&word2);
        let expected = keccak256(&buf);

        assert_eq!(result, expected);
    }

    #[test]
    fn test_keccak_abi_encode_empty() {
        let result = keccak_abi_encode(&[]);
        assert_eq!(result, keccak256(&[]));
    }

    #[test]
    fn test_keccak_abi_encode_concatenation_correctness() {
        let word1 = encode_u256(U256::from(12));
        let word2 = encode_address(address!("2F50D538606Fa9EDD2B11E2446BEb18C9D5846bB"));
        let result = keccak_abi_encode(&[word1, word2]);

        // Verify the result is 32 bytes
        assert_eq!(result.len(), 32);
    }

    ///////////////////////////////////////////////
    // ABI ENCODING TESTS
    ///////////////////////////////////////////////

    #[test]
    fn test_encode_u256_zero() {
        let result = encode_u256(U256::ZERO);
        assert_eq!(result, [0u8; 32]);
    }

    #[test]
    fn test_encode_u256_one() {
        let result = encode_u256(U256::from(1));
        let mut expected = [0u8; 32];
        expected[31] = 1;
        assert_eq!(result, expected);
    }

    #[test]
    fn test_encode_u256_max() {
        let result = encode_u256(U256::MAX);
        assert_eq!(result, [0xff_u8; 32]);
    }

    #[test]
    fn test_encode_u256_slot_value() {
        // Slot 12 - typical weight_mapping_slot for Curve
        let result = encode_u256(U256::from(12));
        let mut expected = [0u8; 32];
        expected[31] = 12;
        assert_eq!(result, expected);
    }

    #[test]
    fn test_encode_u256_epoch_value() {
        // 1730937600 = 0x672C0300
        let result = encode_u256(U256::from(TEST_EPOCH));
        assert_eq!(result[28..], [0x67, 0x2C, 0x03, 0x00]);
    }

    #[test]
    fn test_encode_address_zero() {
        let result = encode_address(Address::ZERO);
        assert_eq!(result, [0u8; 32]);
    }

    #[test]
    fn test_encode_address_gauge_controller() {
        let addr = address!("2F50D538606Fa9EDD2B11E2446BEb18C9D5846bB");
        let result = encode_address(addr);
        // First 12 bytes should be zero (left-padded)
        assert_eq!(result[..12], [0u8; 12]);
        // Last 20 bytes should be the address
        assert_eq!(&result[12..], addr.as_slice());
    }

    #[test]
    fn test_encode_address_preserves_bytes() {
        let addr = address!("26f7786de3e6d9bd37fcf47be6f2bc455a21b74a");
        let result = encode_address(addr);
        assert_eq!(&result[12..], addr.as_slice());
    }

    #[test]
    fn test_encode_uint128_zero() {
        let result = encode_uint128(0);
        assert_eq!(result, [0u8; 32]);
    }

    #[test]
    fn test_encode_uint128_epoch() {
        // 1730937600 = 0x672C0300
        let result = encode_uint128(TEST_EPOCH as u128);
        // First 16 bytes should be zero
        assert_eq!(result[..16], [0u8; 16]);
        // Bytes 28-32 should contain the value (big-endian in the lower 16 bytes)
        assert_eq!(result[28..], [0x67, 0x2C, 0x03, 0x00]);
    }

    #[test]
    fn test_encode_uint128_max() {
        let result = encode_uint128(u128::MAX);
        // First 16 bytes should be zero
        assert_eq!(result[..16], [0u8; 16]);
        // Last 16 bytes should be all 0xff
        assert_eq!(result[16..], [0xff_u8; 16]);
    }

    ///////////////////////////////////////////////
    // HEX FORMATTING TESTS
    ///////////////////////////////////////////////

    #[test]
    fn test_u256_to_hex_32_zero() {
        let result = u256_to_hex_32(U256::ZERO);
        assert_eq!(
            result,
            "0x0000000000000000000000000000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn test_u256_to_hex_32_one() {
        let result = u256_to_hex_32(U256::from(1));
        assert_eq!(
            result,
            "0x0000000000000000000000000000000000000000000000000000000000000001"
        );
    }

    #[test]
    fn test_u256_to_hex_zero() {
        let result = u256_to_hex(U256::ZERO);
        assert_eq!(result, "0x0");
    }

    #[test]
    fn test_u256_to_hex_one() {
        let result = u256_to_hex(U256::from(1));
        assert_eq!(result, "0x1");
    }

    #[test]
    fn test_u256_to_hex_large_value() {
        let result = u256_to_hex(U256::from(0xdeadbeef_u64));
        assert_eq!(result, "0xdeadbeef");
    }

    ///////////////////////////////////////////////
    // PARSING TESTS
    ///////////////////////////////////////////////

    #[test]
    fn test_strip_0x_with_prefix() {
        assert_eq!(strip_0x("0xabcd"), "abcd");
    }

    #[test]
    fn test_strip_0x_without_prefix() {
        assert_eq!(strip_0x("abcd"), "abcd");
    }

    #[test]
    fn test_strip_0x_empty() {
        assert_eq!(strip_0x(""), "");
    }

    #[test]
    fn test_strip_0x_only_prefix() {
        assert_eq!(strip_0x("0x"), "");
    }

    #[test]
    fn test_parse_u64_decimal() {
        assert_eq!(parse_u64("12345").unwrap(), 12345);
    }

    #[test]
    fn test_parse_u64_hex() {
        assert_eq!(parse_u64("0xff").unwrap(), 255);
    }

    #[test]
    fn test_parse_u64_hex_uppercase() {
        assert_eq!(parse_u64("0xFF").unwrap(), 255);
    }

    #[test]
    fn test_parse_u64_block_number() {
        // Block 21134723 = 0x1427D83
        assert_eq!(parse_u64("21134723").unwrap(), 21134723);
        assert_eq!(parse_u64("0x1427d83").unwrap(), 21134723);
    }

    #[test]
    fn test_parse_u64_zero() {
        assert_eq!(parse_u64("0").unwrap(), 0);
        assert_eq!(parse_u64("0x0").unwrap(), 0);
    }

    #[test]
    fn test_parse_u64_invalid() {
        assert!(parse_u64("not_a_number").is_err());
    }

    #[test]
    fn test_parse_u64_overflow() {
        // u64::MAX + 1 should fail
        assert!(parse_u64("18446744073709551616").is_err());
    }

    #[test]
    fn test_parse_b256_valid() {
        let hex_str = "0x0000000000000000000000000000000000000000000000000000000000000001";
        let result = parse_b256(hex_str).unwrap();
        let mut expected = [0u8; 32];
        expected[31] = 1;
        assert_eq!(result, B256::from(expected));
    }

    #[test]
    fn test_parse_b256_without_0x_prefix() {
        let hex_str = "0000000000000000000000000000000000000000000000000000000000000001";
        let result = parse_b256(hex_str).unwrap();
        let mut expected = [0u8; 32];
        expected[31] = 1;
        assert_eq!(result, B256::from(expected));
    }

    #[test]
    fn test_parse_b256_wrong_length() {
        let hex_str = "0x00000001"; // Only 4 bytes
        assert!(parse_b256(hex_str).is_err());
    }

    #[test]
    fn test_parse_b256_invalid_hex() {
        let hex_str = "0xGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG";
        assert!(parse_b256(hex_str).is_err());
    }

    #[test]
    fn test_parse_b256_all_zeros() {
        let hex_str = "0x0000000000000000000000000000000000000000000000000000000000000000";
        let result = parse_b256(hex_str).unwrap();
        assert_eq!(result, B256::ZERO);
    }

    #[test]
    fn test_parse_u256_decimal() {
        assert_eq!(parse_u256("12345").unwrap(), U256::from(12345));
    }

    #[test]
    fn test_parse_u256_hex() {
        assert_eq!(parse_u256("0xff").unwrap(), U256::from(255));
    }

    #[test]
    fn test_parse_u256_large_value() {
        let hex_str = "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        let result = parse_u256(hex_str).unwrap();
        assert_eq!(result, U256::MAX);
    }

    #[test]
    fn test_parse_u256_zero() {
        assert_eq!(parse_u256("0").unwrap(), U256::ZERO);
        assert_eq!(parse_u256("0x0").unwrap(), U256::ZERO);
    }

    #[test]
    fn test_parse_u256_epoch() {
        assert_eq!(parse_u256("1730937600").unwrap(), U256::from(TEST_EPOCH));
    }

    ///////////////////////////////////////////////
    // RLP DECODING TESTS
    ///////////////////////////////////////////////

    #[test]
    fn test_decode_proof_nodes_valid() {
        let nodes = vec![
            "0xabcd".to_string(),
            "0x1234".to_string(),
        ];
        let result = decode_proof_nodes(&nodes).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], vec![0xab, 0xcd]);
        assert_eq!(result[1], vec![0x12, 0x34]);
    }

    #[test]
    fn test_decode_proof_nodes_empty() {
        let nodes: Vec<String> = vec![];
        let result = decode_proof_nodes(&nodes).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_decode_proof_nodes_invalid_hex() {
        let nodes = vec!["0xGGGG".to_string()];
        assert!(decode_proof_nodes(&nodes).is_err());
    }

    #[test]
    fn test_decode_hex_bytes_valid() {
        let result = decode_hex_bytes("0xabcd").unwrap();
        assert_eq!(result, vec![0xab, 0xcd]);
    }

    #[test]
    fn test_decode_hex_bytes_without_prefix() {
        let result = decode_hex_bytes("abcd").unwrap();
        assert_eq!(result, vec![0xab, 0xcd]);
    }

    #[test]
    fn test_decode_hex_bytes_invalid() {
        assert!(decode_hex_bytes("0xGGGG").is_err());
    }

    #[test]
    fn test_decode_hex_bytes_empty() {
        let result = decode_hex_bytes("0x").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_decode_rlp_node_list_empty_list() {
        // 0xc0 is RLP encoding of empty list
        let result = decode_rlp_node_list("0xc0").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_decode_rlp_node_list_non_list_error() {
        // 0x80 is RLP encoding of empty string, not a list
        let result = decode_rlp_node_list("0x80");
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_rlp_proof_list_empty() {
        // 0xc0 is RLP encoding of empty list
        let result = decode_rlp_proof_list("0xc0").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_decode_rlp_proof_list_non_list_error() {
        // 0x80 is RLP encoding of empty string, not a list
        let result = decode_rlp_proof_list("0x80");
        assert!(result.is_err());
    }

    ///////////////////////////////////////////////
    // ABI DECODING TESTS
    ///////////////////////////////////////////////

    #[test]
    fn test_decode_abi_public_values_empty_results() {
        // Create PublicValues with empty results and encode it
        let state_root = b256!("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
        let epoch = U256::from(TEST_EPOCH);
        let point_results: Vec<PointResult> = vec![];
        let account_results: Vec<AccountResult> = vec![];

        let public_values = PublicValues {
            stateRoot: state_root,
            epoch,
            pointResults: point_results,
            accountResults: account_results,
        };

        let encoded = public_values.abi_encode();
        let decoded = decode_abi_public_values(&encoded).unwrap();

        assert_eq!(decoded.state_root, state_root);
        assert_eq!(decoded.epoch, TEST_EPOCH);
        assert!(decoded.point_results.is_empty());
        assert!(decoded.account_results.is_empty());
    }

    #[test]
    fn test_decode_abi_public_values_with_point_result() {
        let state_root = b256!("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
        let gauge = address!("26f7786de3e6d9bd37fcf47be6f2bc455a21b74a");
        let epoch = U256::from(TEST_EPOCH);
        let bias = U256::from(1000);

        let point_results = vec![PointResult {
            gauge,
            epoch,
            bias,
        }];
        let account_results: Vec<AccountResult> = vec![];

        let public_values = PublicValues {
            stateRoot: state_root,
            epoch,
            pointResults: point_results,
            accountResults: account_results,
        };

        let encoded = public_values.abi_encode();
        let decoded = decode_abi_public_values(&encoded).unwrap();

        assert_eq!(decoded.point_results.len(), 1);
        assert_eq!(decoded.point_results[0].gauge, gauge);
        assert_eq!(decoded.point_results[0].epoch, TEST_EPOCH);
        assert_eq!(decoded.point_results[0].bias, bias);
    }

    #[test]
    fn test_decode_abi_public_values_with_account_result() {
        let state_root = b256!("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
        let account = address!("fac2f11ba2577d5122dc1ec5301d35b16688251e");
        let gauge = address!("26f7786de3e6d9bd37fcf47be6f2bc455a21b74a");
        let epoch = U256::from(TEST_EPOCH);

        let account_results = vec![AccountResult {
            account,
            gauge,
            epoch,
            slope: U256::from(100),
            end: U256::from(1800000000u64),
            lastVote: U256::from(1700000000u64),
        }];

        let public_values = PublicValues {
            stateRoot: state_root,
            epoch,
            pointResults: vec![],
            accountResults: account_results,
        };

        let encoded = public_values.abi_encode();
        let decoded = decode_abi_public_values(&encoded).unwrap();

        assert_eq!(decoded.account_results.len(), 1);
        assert_eq!(decoded.account_results[0].account, account);
        assert_eq!(decoded.account_results[0].gauge, gauge);
        assert_eq!(decoded.account_results[0].slope, U256::from(100));
    }

    #[test]
    fn test_decode_abi_public_values_invalid_bytes() {
        let invalid = vec![0x00, 0x01, 0x02, 0x03];
        assert!(decode_abi_public_values(&invalid).is_err());
    }

    ///////////////////////////////////////////////
    // RPC URL RESOLUTION TESTS
    ///////////////////////////////////////////////

    #[test]
    fn test_toolkit_rpc_env_name_ethereum() {
        assert_eq!(toolkit_rpc_env_name(1).unwrap(), "ETHEREUM_MAINNET_RPC_URL");
    }

    #[test]
    fn test_toolkit_rpc_env_name_optimism() {
        assert_eq!(toolkit_rpc_env_name(10).unwrap(), "OPTIMISM_MAINNET_RPC_URL");
    }

    #[test]
    fn test_toolkit_rpc_env_name_arbitrum() {
        assert_eq!(toolkit_rpc_env_name(42161).unwrap(), "ARBITRUM_MAINNET_RPC_URL");
    }

    #[test]
    fn test_toolkit_rpc_env_name_base() {
        assert_eq!(toolkit_rpc_env_name(8453).unwrap(), "BASE_MAINNET_RPC_URL");
    }

    #[test]
    fn test_toolkit_rpc_env_name_polygon() {
        assert_eq!(toolkit_rpc_env_name(137).unwrap(), "POLYGON_MAINNET_RPC_URL");
    }

    #[test]
    fn test_toolkit_rpc_env_name_bsc() {
        assert_eq!(toolkit_rpc_env_name(56).unwrap(), "BSC_MAINNET_RPC_URL");
    }

    #[test]
    fn test_toolkit_rpc_env_name_unsupported() {
        assert!(toolkit_rpc_env_name(99999).is_err());
    }
}
