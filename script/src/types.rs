//! Data structures for host input, requests, and proof artifacts.

use alloy_primitives::Address;
use serde::{Deserialize, Serialize};
use serde_json::json;
use shared::Output;
use std::{env, fs};

use crate::helpers::{
    deserialize_optional_address, parse_address_env, parse_optional_address_env,
    parse_optional_u64_env, u256_to_hex,
};
use crate::protocol::{Protocol, SlotConfig, SlotRequest};

/// Type of proof request.
#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum RequestKind {
    AccountData,
    PointData,
}

/// A single proof request item from JSON input.
#[derive(Debug, Serialize, Deserialize)]
pub struct RequestItem {
    #[serde(rename = "type")]
    pub kind: RequestKind,
    #[serde(default, deserialize_with = "deserialize_optional_address")]
    pub account: Option<Address>,
    #[serde(default, deserialize_with = "deserialize_optional_address")]
    pub gauge: Option<Address>,
}

/// JSON input format for host requests.
#[derive(Debug, Serialize, Deserialize)]
pub struct HostRequest {
    pub chain_id: u64,
    pub block_number: u64,
    #[serde(default)]
    pub epoch: Option<u64>,
    #[serde(default)]
    pub protocol: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_address")]
    pub gauge_controller: Option<Address>,
    #[serde(default)]
    pub slots: Option<SlotConfig>,
    pub requests: Vec<RequestItem>,
}

/// Parsed and validated host input.
#[derive(Debug)]
pub struct HostInput {
    pub chain_id: u64,
    pub block_number: Option<u64>,
    pub epoch_override: Option<u64>,
    pub protocol: Protocol,
    pub protocol_name: String,
    pub gauge_controller: Address,
    pub slots: SlotConfig,
    pub requests: Vec<RequestItem>,
}

impl HostInput {
    /// Load host input from environment variables.
    pub fn from_env() -> Result<Self, String> {
        let chain_id = parse_optional_u64_env("CHAIN_ID").unwrap_or(1);
        let block_number = parse_optional_u64_env("BLOCK_NUMBER");
        let protocol_name = env::var("PROTOCOL")
            .unwrap_or_else(|_| "curve".to_string())
            .to_lowercase();
        let protocol = Protocol::from_name(&protocol_name).ok_or_else(|| {
            format!(
                "unknown protocol '{protocol_name}' (no Default fallback; \
                 use curve, balancer, frax, fxn, yb, pendle)"
            )
        })?;
        let gauge = parse_address_env("GAUGE")?;
        let account = parse_address_env("ACCOUNT")?;
        let epoch_override = parse_optional_u64_env("EPOCH");

        // Gauge controller comes from protocol defaults, with optional env override
        let gauge_controller = parse_optional_address_env("GAUGE_CONTROLLER")
            .or_else(|| protocol.gauge_controller())
            .ok_or_else(|| {
                format!(
                    "No gauge controller for protocol '{protocol_name}'. \
                     Set GAUGE_CONTROLLER env var or use a known protocol (curve, balancer, frax, fxn, pendle, yb)"
                )
            })?;

        // Slots are circuit constants derived from the protocol, never host-supplied:
        // the guest derives the same canonical slots in-circuit, so any host override
        // would desync host-fetched proofs from guest-verified keys.
        let slots = protocol.base_slots();

        Ok(Self {
            chain_id,
            block_number,
            epoch_override,
            protocol,
            protocol_name,
            gauge_controller,
            slots,
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

    /// Load host input from a JSON request.
    pub fn from_request(request: HostRequest) -> Result<Self, String> {
        let protocol_name = request
            .protocol
            .unwrap_or_else(|| "curve".to_string())
            .to_lowercase();
        let protocol = Protocol::from_name(&protocol_name).ok_or_else(|| {
            format!(
                "unknown protocol '{protocol_name}' (no Default fallback; \
                 use curve, balancer, frax, fxn, yb, pendle)"
            )
        })?;

        // Gauge controller comes from request if provided, otherwise from protocol defaults
        let gauge_controller = request
            .gauge_controller
            .or_else(|| protocol.gauge_controller())
            .ok_or_else(|| {
                format!(
                    "No gauge controller for protocol '{protocol_name}'. \
                     Provide gauge_controller in JSON or use a known protocol (curve, balancer, frax, fxn, pendle, yb)"
                )
            })?;

        // Slots are circuit constants derived from the protocol, never request-supplied
        // (the guest derives the same canonical slots in-circuit). A JSON `slots`
        // override is ignored on purpose to keep host and guest aligned.
        let slots = protocol.base_slots();

        Ok(Self {
            chain_id: request.chain_id,
            block_number: Some(request.block_number),
            epoch_override: request.epoch,
            protocol,
            protocol_name,
            gauge_controller,
            slots,
            requests: request.requests,
        })
    }

    /// Load host input from INPUT_JSON env var or fall back to env vars.
    pub fn load() -> Result<Self, String> {
        if let Ok(path) = env::var("INPUT_JSON") {
            let contents = fs::read_to_string(&path)
                .map_err(|err| format!("failed to read INPUT_JSON {path}: {err}"))?;
            let request: HostRequest = serde_json::from_str(&contents)
                .map_err(|err| format!("invalid INPUT_JSON: {err}"))?;
            Self::from_request(request)
        } else {
            Self::from_env()
        }
    }

    /// Convert to JSON value for toolkit input.
    pub fn to_json_value(&self, epoch: u64) -> serde_json::Value {
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

/// Expanded request with computed slot positions.
#[derive(Debug)]
pub struct RequestSlots {
    pub kind: RequestKind,
    pub account: Option<Address>,
    pub gauge: Address,
    pub slots: Vec<SlotRequest>,
}

/// Proof artifact for JSON output.
#[derive(Serialize)]
pub struct ProofArtifact {
    pub program_vkey: String,
    pub proof_kind: String,
    pub proof_bytes: Option<String>,
    pub public_values_raw: String,
    pub public_values_hash: String,
    pub public_values_hash_bn254: String,
    pub output: Output,
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{address, U256};

    // Test fixtures
    const TEST_GAUGE: &str = "0x26f7786de3e6d9bd37fcf47be6f2bc455a21b74a";
    const TEST_ACCOUNT: &str = "0xfac2f11ba2577d5122dc1ec5301d35b16688251e";
    const TEST_EPOCH: u64 = 1730937600;
    const TEST_BLOCK: u64 = 21134723;

    ///////////////////////////////////////////////
    // REQUEST KIND TESTS
    ///////////////////////////////////////////////

    #[test]
    fn test_request_kind_deserialize_account_data() {
        let json = r#""account_data""#;
        let kind: RequestKind = serde_json::from_str(json).unwrap();
        assert!(matches!(kind, RequestKind::AccountData));
    }

    #[test]
    fn test_request_kind_deserialize_point_data() {
        let json = r#""point_data""#;
        let kind: RequestKind = serde_json::from_str(json).unwrap();
        assert!(matches!(kind, RequestKind::PointData));
    }

    #[test]
    fn test_request_kind_serialize_account_data() {
        let json = serde_json::to_string(&RequestKind::AccountData).unwrap();
        assert_eq!(json, r#""account_data""#);
    }

    #[test]
    fn test_request_kind_serialize_point_data() {
        let json = serde_json::to_string(&RequestKind::PointData).unwrap();
        assert_eq!(json, r#""point_data""#);
    }

    ///////////////////////////////////////////////
    // REQUEST ITEM TESTS
    ///////////////////////////////////////////////

    #[test]
    fn test_request_item_point_data() {
        let json = format!(r#"{{"type": "point_data", "gauge": "{TEST_GAUGE}"}}"#);
        let item: RequestItem = serde_json::from_str(&json).unwrap();
        assert!(matches!(item.kind, RequestKind::PointData));
        assert!(item.account.is_none());
        assert!(item.gauge.is_some());
    }

    #[test]
    fn test_request_item_account_data() {
        let json = format!(
            r#"{{"type": "account_data", "account": "{TEST_ACCOUNT}", "gauge": "{TEST_GAUGE}"}}"#
        );
        let item: RequestItem = serde_json::from_str(&json).unwrap();
        assert!(matches!(item.kind, RequestKind::AccountData));
        assert!(item.account.is_some());
        assert!(item.gauge.is_some());
    }

    #[test]
    fn test_request_item_null_account() {
        let json = format!(r#"{{"type": "point_data", "account": null, "gauge": "{TEST_GAUGE}"}}"#);
        let item: RequestItem = serde_json::from_str(&json).unwrap();
        assert!(item.account.is_none());
    }

    #[test]
    fn test_request_item_missing_optional_fields() {
        let json = r#"{"type": "point_data"}"#;
        let item: RequestItem = serde_json::from_str(json).unwrap();
        assert!(item.account.is_none());
        assert!(item.gauge.is_none());
    }

    ///////////////////////////////////////////////
    // HOST REQUEST TESTS
    ///////////////////////////////////////////////

    #[test]
    fn test_host_request_minimal() {
        let json = format!(
            r#"{{
                "chain_id": 1,
                "block_number": {TEST_BLOCK},
                "requests": []
            }}"#
        );
        let request: HostRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(request.chain_id, 1);
        assert_eq!(request.block_number, TEST_BLOCK);
        assert!(request.epoch.is_none());
        assert!(request.protocol.is_none());
        assert!(request.gauge_controller.is_none());
        assert!(request.slots.is_none());
        assert!(request.requests.is_empty());
    }

    #[test]
    fn test_host_request_full() {
        let json = format!(
            r#"{{
                "chain_id": 1,
                "block_number": {TEST_BLOCK},
                "epoch": {TEST_EPOCH},
                "protocol": "curve",
                "gauge_controller": "0x2F50D538606Fa9EDD2B11E2446BEb18C9D5846bB",
                "slots": {{
                    "weight_mapping_slot": "12",
                    "last_vote_mapping_slot": "11",
                    "user_slope_mapping_slot": "9"
                }},
                "requests": [
                    {{"type": "point_data", "gauge": "{TEST_GAUGE}"}},
                    {{"type": "account_data", "account": "{TEST_ACCOUNT}", "gauge": "{TEST_GAUGE}"}}
                ]
            }}"#
        );
        let request: HostRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(request.chain_id, 1);
        assert_eq!(request.block_number, TEST_BLOCK);
        assert_eq!(request.epoch, Some(TEST_EPOCH));
        assert_eq!(request.protocol, Some("curve".to_string()));
        assert!(request.gauge_controller.is_some());
        assert!(request.slots.is_some());
        assert_eq!(request.requests.len(), 2);
    }

    ///////////////////////////////////////////////
    // HOST INPUT FROM_REQUEST TESTS
    ///////////////////////////////////////////////

    #[test]
    fn test_host_input_from_request_curve_defaults() {
        let request = HostRequest {
            chain_id: 1,
            block_number: TEST_BLOCK,
            epoch: Some(TEST_EPOCH),
            protocol: Some("curve".to_string()),
            gauge_controller: None, // Should use default
            slots: None,            // Should use default
            requests: vec![],
        };
        let input = HostInput::from_request(request).unwrap();
        assert_eq!(input.chain_id, 1);
        assert_eq!(input.block_number, Some(TEST_BLOCK));
        assert_eq!(input.epoch_override, Some(TEST_EPOCH));
        assert!(matches!(input.protocol, Protocol::Curve));
        assert_eq!(
            input.gauge_controller,
            address!("2F50D538606Fa9EDD2B11E2446BEb18C9D5846bB")
        );
        assert_eq!(input.slots.weight_mapping_slot, U256::from(12));
    }

    #[test]
    fn test_host_input_from_request_ignores_slot_override() {
        // Slots are circuit constants: a JSON `slots` override is ignored in favor of
        // the protocol's canonical base slots, so host and guest stay aligned.
        let request = HostRequest {
            chain_id: 1,
            block_number: TEST_BLOCK,
            epoch: None,
            protocol: Some("curve".to_string()),
            gauge_controller: None,
            slots: Some(crate::protocol::SlotConfig {
                weight_mapping_slot: U256::from(100),
                last_vote_mapping_slot: U256::from(101),
                user_slope_mapping_slot: U256::from(102),
            }),
            requests: vec![],
        };
        let input = HostInput::from_request(request).unwrap();
        let canonical = crate::protocol::Protocol::Curve.base_slots();
        assert_eq!(
            input.slots.weight_mapping_slot,
            canonical.weight_mapping_slot
        );
        assert_eq!(
            input.slots.last_vote_mapping_slot,
            canonical.last_vote_mapping_slot
        );
        assert_eq!(
            input.slots.user_slope_mapping_slot,
            canonical.user_slope_mapping_slot
        );
    }

    #[test]
    fn test_host_input_from_request_unknown_protocol_error() {
        let request = HostRequest {
            chain_id: 1,
            block_number: TEST_BLOCK,
            epoch: None,
            protocol: Some("unknown_protocol".to_string()),
            gauge_controller: None,
            slots: None,
            requests: vec![],
        };
        let result = HostInput::from_request(request);
        assert!(result.is_err());
    }

    #[test]
    fn test_host_input_from_request_balancer() {
        let request = HostRequest {
            chain_id: 1,
            block_number: TEST_BLOCK,
            epoch: None,
            protocol: Some("balancer".to_string()),
            gauge_controller: None,
            slots: None,
            requests: vec![],
        };
        let input = HostInput::from_request(request).unwrap();
        assert!(matches!(input.protocol, Protocol::Balancer));
        assert_eq!(
            input.gauge_controller,
            address!("C128468b7Ce63eA702C1f104D55A2566b13D3ABD")
        );
    }

    #[test]
    fn test_host_input_from_request_pendle() {
        let request = HostRequest {
            chain_id: 1,
            block_number: TEST_BLOCK,
            epoch: None,
            protocol: Some("pendle".to_string()),
            gauge_controller: None,
            slots: None,
            requests: vec![],
        };
        let input = HostInput::from_request(request).unwrap();
        assert!(matches!(input.protocol, Protocol::Pendle));
        assert_eq!(input.slots.last_vote_mapping_slot, U256::ZERO); // Pendle has no last_vote
    }

    ///////////////////////////////////////////////
    // HOST INPUT TO_JSON_VALUE TESTS
    ///////////////////////////////////////////////

    #[test]
    fn test_host_input_to_json_value_correct_structure() {
        let request = HostRequest {
            chain_id: 1,
            block_number: TEST_BLOCK,
            epoch: None,
            protocol: Some("curve".to_string()),
            gauge_controller: None,
            slots: None,
            requests: vec![RequestItem {
                kind: RequestKind::PointData,
                account: None,
                gauge: Some(address!("26f7786de3e6d9bd37fcf47be6f2bc455a21b74a")),
            }],
        };
        let input = HostInput::from_request(request).unwrap();
        let json = input.to_json_value(TEST_EPOCH);

        assert_eq!(json["chain_id"], 1);
        assert_eq!(json["block_number"], TEST_BLOCK);
        assert_eq!(json["epoch"], TEST_EPOCH);
        assert_eq!(json["protocol"], "curve");
        assert!(json["gauge_controller"].is_string());
        assert!(json["slots"].is_object());
        assert!(json["requests"].is_array());
    }

    #[test]
    fn test_host_input_to_json_value_slot_format() {
        let request = HostRequest {
            chain_id: 1,
            block_number: TEST_BLOCK,
            epoch: None,
            protocol: Some("curve".to_string()),
            gauge_controller: None,
            slots: None,
            requests: vec![],
        };
        let input = HostInput::from_request(request).unwrap();
        let json = input.to_json_value(TEST_EPOCH);

        // Slots should be hex formatted
        let weight_slot = json["slots"]["weight_mapping_slot"].as_str().unwrap();
        assert!(weight_slot.starts_with("0x"));
    }

    #[test]
    fn test_host_input_to_json_value_request_format() {
        let request = HostRequest {
            chain_id: 1,
            block_number: TEST_BLOCK,
            epoch: None,
            protocol: Some("curve".to_string()),
            gauge_controller: None,
            slots: None,
            requests: vec![RequestItem {
                kind: RequestKind::AccountData,
                account: Some(address!("fac2f11ba2577d5122dc1ec5301d35b16688251e")),
                gauge: Some(address!("26f7786de3e6d9bd37fcf47be6f2bc455a21b74a")),
            }],
        };
        let input = HostInput::from_request(request).unwrap();
        let json = input.to_json_value(TEST_EPOCH);

        let requests = json["requests"].as_array().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0]["type"], "account_data");
        assert!(requests[0]["account"].is_string());
        assert!(requests[0]["gauge"].is_string());
    }
}
