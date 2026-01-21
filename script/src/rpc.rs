//! Ethereum JSON-RPC client for fetching blocks and proofs.

use alloy_primitives::{Address, B256, U256};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::helpers::{parse_b256, parse_u64, u256_to_hex_32};

///////////////////////////////////////////////
// RPC TYPES
///////////////////////////////////////////////

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
pub struct StorageProof {
    #[serde(rename = "proof")]
    pub proof: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct ProofResponse {
    #[serde(rename = "accountProof")]
    pub account_proof: Vec<String>,
    #[serde(rename = "storageProof")]
    pub storage_proof: Vec<StorageProof>,
}

///////////////////////////////////////////////
// RPC FUNCTIONS
///////////////////////////////////////////////

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
        return Err(format!("RPC status error {status}: {body}"));
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

/// Fetch the latest block number from the RPC.
pub async fn fetch_latest_block_number(
    client: &reqwest::Client,
    rpc_url: &str,
) -> Result<u64, String> {
    let response: String = rpc_call(client, rpc_url, "eth_blockNumber", json!([])).await?;
    parse_u64(&response)
}

/// Fetch block state root and timestamp.
pub async fn fetch_block_state_root(
    client: &reqwest::Client,
    rpc_url: &str,
    block_number: u64,
) -> Result<(B256, u64), String> {
    let block_number_hex = format!("0x{block_number:x}");
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

/// Fetch account and storage proofs using eth_getProof.
pub async fn fetch_proofs(
    client: &reqwest::Client,
    rpc_url: &str,
    gauge_controller: Address,
    block_number: u64,
    slots: &[U256],
) -> Result<ProofResponse, String> {
    let block_number_hex = format!("0x{block_number:x}");
    let slot_hexes: Vec<String> = slots.iter().map(|slot| u256_to_hex_32(*slot)).collect();

    rpc_call(
        client,
        rpc_url,
        "eth_getProof",
        json!([gauge_controller.to_string(), slot_hexes, block_number_hex]),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::U256;

    ///////////////////////////////////////////////
    // STORAGE PROOF DESERIALIZATION TESTS
    ///////////////////////////////////////////////

    #[test]
    fn test_storage_proof_deserialize() {
        let json = r#"{
            "proof": ["0xabcd", "0x1234"]
        }"#;
        let proof: StorageProof = serde_json::from_str(json).unwrap();
        assert_eq!(proof.proof.len(), 2);
        assert_eq!(proof.proof[0], "0xabcd");
        assert_eq!(proof.proof[1], "0x1234");
    }

    #[test]
    fn test_storage_proof_deserialize_empty() {
        let json = r#"{
            "proof": []
        }"#;
        let proof: StorageProof = serde_json::from_str(json).unwrap();
        assert!(proof.proof.is_empty());
    }

    ///////////////////////////////////////////////
    // PROOF RESPONSE DESERIALIZATION TESTS
    ///////////////////////////////////////////////

    #[test]
    fn test_proof_response_deserialize() {
        let json = r#"{
            "accountProof": ["0xf851", "0xf871"],
            "storageProof": [
                {"proof": ["0x1234", "0x5678"]},
                {"proof": ["0xabcd"]}
            ]
        }"#;
        let response: ProofResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.account_proof.len(), 2);
        assert_eq!(response.storage_proof.len(), 2);
        assert_eq!(response.storage_proof[0].proof.len(), 2);
        assert_eq!(response.storage_proof[1].proof.len(), 1);
    }

    #[test]
    fn test_proof_response_deserialize_empty_storage() {
        let json = r#"{
            "accountProof": ["0xf851"],
            "storageProof": []
        }"#;
        let response: ProofResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.account_proof.len(), 1);
        assert!(response.storage_proof.is_empty());
    }

    ///////////////////////////////////////////////
    // HEX FORMATTING TESTS
    ///////////////////////////////////////////////

    #[test]
    fn test_u256_to_hex_32_formatting() {
        let slot = U256::from(12);
        let hex = u256_to_hex_32(slot);
        assert_eq!(hex.len(), 66); // "0x" + 64 hex chars
        assert!(hex.starts_with("0x"));
    }

    #[test]
    fn test_slot_hex_vector_formatting() {
        let slots = [U256::from(9), U256::from(11), U256::from(12)];
        let slot_hexes: Vec<String> = slots.iter().map(|s| u256_to_hex_32(*s)).collect();
        assert_eq!(slot_hexes.len(), 3);
        for hex in &slot_hexes {
            assert!(hex.starts_with("0x"));
            assert_eq!(hex.len(), 66);
        }
    }
}
