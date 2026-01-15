//! Data structures for host input, requests, and proof artifacts.

use alloy_primitives::Address;
use serde::{Deserialize, Serialize};
use serde_json::json;
use shared::Output;
use std::{env, fs};

use crate::helpers::{
    deserialize_optional_address, parse_address_env, parse_optional_address_env,
    parse_optional_u256_env, parse_optional_u64_env, u256_to_hex,
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
        let protocol = Protocol::from_str(&protocol_name);
        let gauge = parse_address_env("GAUGE")?;
        let account = parse_address_env("ACCOUNT")?;
        let epoch_override = parse_optional_u64_env("EPOCH");

        // Gauge controller comes from protocol defaults, with optional env override
        let gauge_controller = parse_optional_address_env("GAUGE_CONTROLLER")
            .or_else(|| protocol.gauge_controller())
            .ok_or_else(|| {
                format!(
                    "No gauge controller for protocol '{}'. \
                     Set GAUGE_CONTROLLER env var or use a known protocol (curve, balancer, frax, fxn, pendle, yb)",
                    protocol_name
                )
            })?;

        // Slots are optional - they can come from env vars or from toolkit defaults
        let weight_mapping_slot = parse_optional_u256_env("WEIGHT_MAPPING_SLOT");
        let last_vote_mapping_slot = parse_optional_u256_env("LAST_VOTE_MAPPING_SLOT");
        let user_slope_mapping_slot = parse_optional_u256_env("USER_SLOPE_MAPPING_SLOT");

        // Use env slots if all are provided, otherwise use toolkit defaults for the protocol
        let slots = match (weight_mapping_slot, last_vote_mapping_slot, user_slope_mapping_slot) {
            (Some(w), Some(l), Some(u)) => SlotConfig {
                weight_mapping_slot: w,
                last_vote_mapping_slot: l,
                user_slope_mapping_slot: u,
            },
            _ => {
                // Try to use toolkit defaults
                protocol.toolkit_slots().ok_or_else(|| {
                    format!(
                        "Missing slot env vars and no toolkit defaults for protocol '{}'. \
                         Set WEIGHT_MAPPING_SLOT, LAST_VOTE_MAPPING_SLOT, USER_SLOPE_MAPPING_SLOT \
                         or use a protocol with toolkit defaults (curve, balancer, frax, fxn, pendle, yb)",
                        protocol_name
                    )
                })?
            }
        };

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
        let protocol = Protocol::from_str(&protocol_name);

        // Gauge controller comes from request if provided, otherwise from protocol defaults
        let gauge_controller = request
            .gauge_controller
            .or_else(|| protocol.gauge_controller())
            .ok_or_else(|| {
                format!(
                    "No gauge controller for protocol '{}'. \
                     Provide gauge_controller in JSON or use a known protocol (curve, balancer, frax, fxn, pendle, yb)",
                    protocol_name
                )
            })?;

        // Slots come from request if provided, otherwise from protocol defaults
        let slots = request
            .slots
            .or_else(|| protocol.toolkit_slots())
            .ok_or_else(|| {
                format!(
                    "No slots for protocol '{}'. \
                     Provide slots in JSON or use a known protocol (curve, balancer, frax, fxn, pendle, yb)",
                    protocol_name
                )
            })?;

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
                .map_err(|err| format!("failed to read INPUT_JSON {}: {err}", path))?;
            let request: HostRequest =
                serde_json::from_str(&contents).map_err(|err| format!("invalid INPUT_JSON: {err}"))?;
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
