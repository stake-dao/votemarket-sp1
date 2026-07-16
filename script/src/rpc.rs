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
// INGESTION LIMITS
///////////////////////////////////////////////

/// Cap on a single RPC response body, enforced while the body streams in so an
/// oversized one is never buffered whole. A mainnet `eth_getProof` response for a
/// batch of slots is a few KB, so this is a generous ceiling on an untrusted peer.
pub const MAX_RPC_BODY_BYTES: usize = 8 * 1024 * 1024;

///////////////////////////////////////////////
// ERROR SANITIZING
///////////////////////////////////////////////

/// Format a `reqwest` error without the request URL.
///
/// `reqwest::Error`'s `Display` embeds the URL it was building, and RPC providers
/// (Alchemy, Infura) carry the API key in the URL path, so the default formatting
/// leaks the credential into logs and panics. `without_url` drops it, and the
/// wrapped `source()` chain is transport-level and never carries the URL.
fn sanitize_reqwest_error(context: &str, err: reqwest::Error) -> String {
    format!("{context}: {}", err.without_url())
}

/// Cap on how much of an error response body is quoted back in an error message.
const MAX_QUOTED_BODY_BYTES: usize = 512;

/// Shortest URL path worth scrubbing on its own.
///
/// A bare `/`, or a short prefix like `/v2`, carries no credential but occurs all
/// over ordinary text, so replacing it would rewrite every slash in a diagnostic
/// and destroy it. Only a path long enough to plausibly hold a key is scrubbed.
const MIN_REDACTABLE_PATH: usize = 8;

/// Make remote-controlled text safe to put in an error message.
///
/// The body and the JSON-RPC `error.message` are both written by the peer: a
/// provider (or anything impersonating one) can echo the request URL — which
/// carries the API key for key-in-path providers — back at us, and can embed
/// control characters that would garble a terminal. Scrub the URL, drop control
/// characters, and bound the length.
///
/// Known limit: this is substring replacement, so a query-only echo
/// (`apikey=SECRET` with no leading slash) or a re-encoded rendering survives it.
/// It bounds accidental disclosure from an ordinary provider error, not a peer
/// deliberately trying to smuggle the key back past it.
fn sanitize_body(body: &str, url: &str) -> String {
    let mut safe = body.replace(url, "<redacted-rpc-url>");
    if let Some((_, path_and_query)) = split_url_origin(url) {
        if path_and_query.len() >= MIN_REDACTABLE_PATH {
            safe = safe.replace(path_and_query, "/<redacted>");
        }
    }

    let mut out: String = safe
        .chars()
        .map(|c| {
            if c == '\n' || c == '\t' || !c.is_control() {
                c
            } else {
                '?'
            }
        })
        .collect();

    // Measure and cut in the same unit. Counting bytes but taking chars would let a
    // multibyte body run several times past the budget.
    if out.len() > MAX_QUOTED_BODY_BYTES {
        let mut cut = MAX_QUOTED_BODY_BYTES;
        while cut > 0 && !out.is_char_boundary(cut) {
            cut -= 1;
        }
        out.truncate(cut);
        out.push_str("... <truncated>");
    }
    out
}

/// Split a URL into its `scheme://host[:port]` origin and the remaining path+query.
fn split_url_origin(url: &str) -> Option<(&str, &str)> {
    let scheme_end = url.find("://")? + 3;
    let rest = &url[scheme_end..];
    match rest.find('/') {
        Some(idx) => Some((&url[..scheme_end + idx], &rest[idx..])),
        None => Some((url, "")),
    }
}

///////////////////////////////////////////////
// RPC FUNCTIONS
///////////////////////////////////////////////

/// Read a response body, refusing one that exceeds `limit`.
///
/// The bound is enforced chunk by chunk rather than via `text()`, so a hostile or
/// broken peer cannot force an unbounded allocation before we get to inspect it.
/// A `Content-Length` over the cap is refused up front, but it is only a hint: the
/// streaming check below is what actually holds.
async fn read_body_bounded(
    mut response: reqwest::Response,
    limit: usize,
) -> Result<String, String> {
    if let Some(advertised) = response.content_length() {
        if advertised > limit as u64 {
            return Err(format!(
                "RPC response too large: content-length {advertised} exceeds the {limit} byte cap"
            ));
        }
    }

    let mut body: Vec<u8> = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|err| sanitize_reqwest_error("RPC response read failed", err))?
    {
        if body.len() + chunk.len() > limit {
            return Err(format!(
                "RPC response too large: exceeds the {limit} byte cap"
            ));
        }
        body.extend_from_slice(&chunk);
    }

    String::from_utf8(body).map_err(|_| "RPC response is not valid UTF-8".to_string())
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
        .map_err(|err| sanitize_reqwest_error("RPC request failed", err))?;

    let status = response.status();
    let body = read_body_bounded(response, MAX_RPC_BODY_BYTES).await?;

    if !status.is_success() {
        return Err(format!(
            "RPC status error {status}: {}",
            sanitize_body(&body, url)
        ));
    }

    let rpc_response: RpcResponse<T> =
        serde_json::from_str(&body).map_err(|err| format!("RPC decode failed: {err}"))?;

    if let Some(error) = rpc_response.error {
        // A 200 carrying a JSON-RPC error object is the ordinary way a provider
        // reports a rate limit or a bad key, and `message` is its text, not ours:
        // it gets the same scrub as any other remote-controlled string.
        return Err(format!(
            "RPC error {}: {}",
            error.code,
            sanitize_body(&error.message, url)
        ));
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
    use std::error::Error;

    ///////////////////////////////////////////////
    // CREDENTIAL LEAK TESTS
    ///////////////////////////////////////////////

    /// Walk an error's full `source()` chain, so a credential hiding in a wrapped
    /// cause is caught rather than only the top-level message.
    fn full_error_chain(err: &dyn Error) -> String {
        let mut chain = err.to_string();
        let mut current = err.source();
        while let Some(cause) = current {
            chain.push_str(&format!(" | {cause}"));
            current = cause.source();
        }
        chain
    }

    // The credential lives in the URL path for the providers this host talks to, so
    // a transport error must not surface it. Port 1 on loopback refuses instantly,
    // which produces a real reqwest transport error without leaving the machine.
    #[tokio::test]
    async fn test_transport_error_does_not_leak_url_credential() {
        const SECRET: &str = "s3cret-api-key-do-not-log";
        let url = format!("http://127.0.0.1:1/v2/{SECRET}?apikey={SECRET}");

        let client = reqwest::Client::new();
        let err = client
            .post(&url)
            .json(&json!({}))
            .send()
            .await
            .expect_err("connection to port 1 must fail");

        // The raw error is the thing being guarded against: assert it really does
        // carry the credential, so this test cannot silently pass on a reqwest that
        // stopped embedding URLs.
        assert!(
            full_error_chain(&err).contains(SECRET),
            "precondition: the raw reqwest error is expected to carry the URL"
        );

        let sanitized = sanitize_reqwest_error("RPC request failed", err);
        assert!(
            !sanitized.contains(SECRET),
            "sanitized error leaked the credential: {sanitized}"
        );
        assert!(!sanitized.contains("127.0.0.1"));
        assert!(sanitized.contains("RPC request failed"));
    }

    // A provider's error body is remote-controlled text and can echo the request URL
    // straight back, so the status-error path must scrub it too, not just the
    // reqwest error.
    #[tokio::test]
    async fn test_status_error_body_does_not_leak_url_credential() {
        const SECRET: &str = "s3cret-api-key-do-not-log";
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{addr}/v2/{SECRET}");

        let echo = url.clone();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            // A hostile-or-chatty provider quoting the full request URL, plus a
            // control character that would otherwise garble the terminal.
            let payload = format!("{{\"error\":\"401 unauthorized for {echo}\"}}\x1b[31m");
            let response = format!(
                "HTTP/1.1 401 Unauthorized\r\nContent-Length: {}\r\n\r\n{}",
                payload.len(),
                payload
            );
            use tokio::io::AsyncWriteExt;
            let _ = socket.write_all(response.as_bytes()).await;
        });

        let client = reqwest::Client::new();
        let result: Result<serde_json::Value, String> =
            rpc_call(&client, &url, "eth_blockNumber", json!([])).await;

        let err = result.expect_err("a 401 must surface as an error");
        assert!(err.contains("401"), "status should survive: {err}");
        assert!(
            !err.contains(SECRET),
            "status error leaked credential: {err}"
        );
        assert!(
            !err.contains('\x1b'),
            "control chars must be escaped: {err}"
        );
    }

    #[test]
    fn test_sanitize_body_bounds_length() {
        let url = "https://host.example/v2/key";
        let huge = "x".repeat(MAX_QUOTED_BODY_BYTES * 4);
        let out = sanitize_body(&huge, url);
        assert!(out.len() < MAX_QUOTED_BODY_BYTES + 32);
        assert!(out.ends_with("<truncated>"));
    }

    // The budget is in bytes, so the cut must be too. Counting bytes but taking
    // chars would let a multibyte body run several times past it.
    #[test]
    fn test_sanitize_body_bound_is_bytes_not_chars() {
        let url = "https://host.example/v2/key";
        // 3 bytes per char: a char-based cut would emit ~3x the byte budget.
        let multibyte = "あ".repeat(MAX_QUOTED_BODY_BYTES);
        let out = sanitize_body(&multibyte, url);
        assert!(
            out.len() < MAX_QUOTED_BODY_BYTES + 32,
            "byte budget blown: {} bytes",
            out.len()
        );
    }

    // A JSON-RPC error object on a 200 is the ordinary rate-limit / bad-key shape,
    // and its message is written by the peer, so it must be scrubbed like any other
    // remote text rather than trusted because the status was 200.
    #[tokio::test]
    async fn test_jsonrpc_error_object_does_not_leak_url_credential() {
        const SECRET: &str = "s3cret-api-key-do-not-log";
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{addr}/v2/{SECRET}");

        let echo = url.clone();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let payload = format!(
                "{{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{{\"code\":-32000,\"message\":\"rate limited for {echo}\"}}}}"
            );
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                payload.len(),
                payload
            );
            use tokio::io::AsyncWriteExt;
            let _ = socket.write_all(response.as_bytes()).await;
        });

        let client = reqwest::Client::new();
        let result: Result<serde_json::Value, String> =
            rpc_call(&client, &url, "eth_blockNumber", json!([])).await;

        let err = result.expect_err("a JSON-RPC error object must surface as an error");
        assert!(err.contains("-32000"), "code should survive: {err}");
        assert!(
            !err.contains(SECRET),
            "error object leaked credential: {err}"
        );
    }

    // A URL whose path is just `/` must not turn every slash in the text into a
    // redaction marker: that destroys the diagnostic while protecting nothing.
    #[test]
    fn test_sanitize_body_does_not_over_redact_short_paths() {
        let out = sanitize_body("failed at /eth/v1/foo and /bar", "https://host.example/");
        assert!(out.contains("/eth/v1/foo"), "over-redacted: {out}");
        assert!(!out.contains("<redacted>"), "over-redacted: {out}");
    }

    #[test]
    fn test_split_url_origin_rpc() {
        assert_eq!(
            split_url_origin("https://host.example/v2/key"),
            Some(("https://host.example", "/v2/key"))
        );
        assert_eq!(split_url_origin("not-a-url"), None);
    }

    ///////////////////////////////////////////////
    // BODY BOUND TESTS
    ///////////////////////////////////////////////

    // The cap must reject before the body is parsed, so an oversized response is
    // never turned into a Vec of proof nodes.
    #[tokio::test]
    async fn test_oversized_body_rejected_before_deserialization() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Serve a body far past the cap, streamed so the client sees it arrive.
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let oversized = "a".repeat(MAX_RPC_BODY_BYTES + 1024);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                oversized.len(),
                oversized
            );
            use tokio::io::AsyncWriteExt;
            let _ = socket.write_all(response.as_bytes()).await;
        });

        let client = reqwest::Client::new();
        let result: Result<serde_json::Value, String> = rpc_call(
            &client,
            &format!("http://{addr}"),
            "eth_blockNumber",
            json!([]),
        )
        .await;

        let err = result.expect_err("oversized body must be refused");
        assert!(
            err.contains("too large"),
            "expected a size refusal, got: {err}"
        );
    }

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
