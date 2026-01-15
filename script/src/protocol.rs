//! Protocol definitions and storage slot calculations.
//!
//! This module contains protocol-specific logic for computing Ethereum storage slots
//! based on different Vyper compiler versions and contract layouts.

use alloy_primitives::{address, Address, U256};
use serde::{Deserialize, Serialize};

use crate::helpers::{deserialize_u256, encode_address, encode_u256, encode_uint128, keccak_abi_encode};

/// Supported protocols with their specific storage layouts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Curve,
    Balancer,
    Frax,
    Fxn,
    Yb,
    Pendle,
    Default,
}

impl Protocol {
    pub fn from_str(value: &str) -> Self {
        match value.to_lowercase().as_str() {
            "curve" => Self::Curve,
            "balancer" => Self::Balancer,
            "frax" => Self::Frax,
            "fxn" => Self::Fxn,
            "yb" => Self::Yb,
            "pendle" => Self::Pendle,
            _ => Self::Default,
        }
    }

    /// Get the toolkit's hardcoded slot values for this protocol.
    /// These MUST match the values in votemarket_toolkit/shared/registry.py
    pub fn toolkit_slots(&self) -> Option<SlotConfig> {
        match self {
            Protocol::Curve => Some(SlotConfig {
                weight_mapping_slot: U256::from(12),
                last_vote_mapping_slot: U256::from(11),
                user_slope_mapping_slot: U256::from(9),
            }),
            Protocol::Balancer => Some(SlotConfig {
                weight_mapping_slot: U256::from(1000000008u64),
                last_vote_mapping_slot: U256::from(1000000007u64),
                user_slope_mapping_slot: U256::from(1000000005u64),
            }),
            Protocol::Frax => Some(SlotConfig {
                weight_mapping_slot: U256::from(1000000011u64),
                last_vote_mapping_slot: U256::from(1000000010u64),
                user_slope_mapping_slot: U256::from(1000000008u64),
            }),
            Protocol::Fxn => Some(SlotConfig {
                weight_mapping_slot: U256::from(1000000011u64),
                last_vote_mapping_slot: U256::from(1000000010u64),
                user_slope_mapping_slot: U256::from(1000000008u64),
            }),
            Protocol::Pendle => Some(SlotConfig {
                weight_mapping_slot: U256::from(161),
                last_vote_mapping_slot: U256::ZERO, // Pendle has no last_user_vote
                user_slope_mapping_slot: U256::from(162),
            }),
            Protocol::Yb => Some(SlotConfig {
                weight_mapping_slot: U256::from(1000000006u64),
                last_vote_mapping_slot: U256::from(1000000005u64),
                user_slope_mapping_slot: U256::from(1000000003u64),
            }),
            Protocol::Default => None,
        }
    }

    /// Get the gauge controller address for this protocol.
    /// These MUST match the values in votemarket_toolkit/shared/constants.py
    pub fn gauge_controller(&self) -> Option<Address> {
        match self {
            Protocol::Curve => Some(address!("2F50D538606Fa9EDD2B11E2446BEb18C9D5846bB")),
            Protocol::Balancer => Some(address!("C128468b7Ce63eA702C1f104D55A2566b13D3ABD")),
            Protocol::Frax => Some(address!("3669C421b77340B2979d1A00a792CC2ee0FcE737")),
            Protocol::Fxn => Some(address!("e60eB8098B34eD775ac44B1ddE864e098C6d7f37")),
            Protocol::Pendle => Some(address!("44087E105137a5095c008AaB6a6530182821F2F0")),
            Protocol::Yb => Some(address!("1Be14811A3a06F6aF4fA64310a636e1Df04c1c21")),
            Protocol::Default => None,
        }
    }
}

/// Storage slot configuration for a protocol's GaugeController.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct SlotConfig {
    #[serde(deserialize_with = "deserialize_u256")]
    pub weight_mapping_slot: U256,
    #[serde(deserialize_with = "deserialize_u256")]
    pub last_vote_mapping_slot: U256,
    #[serde(deserialize_with = "deserialize_u256")]
    pub user_slope_mapping_slot: U256,
}

/// Expanded slot information for a single request.
#[derive(Debug, Clone)]
pub struct SlotRequest {
    pub label: String,
    pub slot: U256,
}

///////////////////////////////////////////////
// GAUGE SLOT CALCULATIONS
///////////////////////////////////////////////

/// Compute the storage slot for gauge point data based on protocol.
pub fn gauge_time_slot(protocol: Protocol, gauge: Address, epoch: u64, base_slot: U256) -> U256 {
    match protocol {
        Protocol::Curve => gauge_time_slot_pre_vyper03(gauge, epoch, base_slot),
        Protocol::Yb => gauge_time_slot_yb(gauge, base_slot),
        Protocol::Pendle => gauge_time_slot_pendle(gauge, epoch, base_slot),
        // Balancer, Frax, Fxn use Vyper 0.3+ default slot calculation
        Protocol::Balancer | Protocol::Frax | Protocol::Fxn | Protocol::Default => {
            gauge_time_slot_default(gauge, epoch, base_slot)
        }
    }
}

/// Default slot calculation for Vyper 0.3+ contracts.
/// Layout: points_weight[gauge][epoch].bias
fn gauge_time_slot_default(gauge: Address, epoch: u64, base_slot: U256) -> U256 {
    let gauge_encoded = keccak_abi_encode(&[encode_u256(base_slot), encode_address(gauge)]);
    let inner = keccak_abi_encode(&[gauge_encoded, encode_u256(U256::from(epoch))]);
    U256::from_be_bytes(inner)
}

/// Pre-Vyper 0.3 slot calculation (used by Curve).
/// Has an extra hash layer compared to default.
fn gauge_time_slot_pre_vyper03(gauge: Address, epoch: u64, base_slot: U256) -> U256 {
    let gauge_encoded = keccak_abi_encode(&[encode_u256(base_slot), encode_address(gauge)]);
    let inner = keccak_abi_encode(&[gauge_encoded, encode_u256(U256::from(epoch))]);
    let final_hash = keccak_abi_encode(&[inner]);
    U256::from_be_bytes(final_hash)
}

/// YieldBox-specific slot calculation.
/// Doesn't use epoch in the slot path.
fn gauge_time_slot_yb(gauge: Address, base_slot: U256) -> U256 {
    let gauge_encoded = keccak_abi_encode(&[encode_u256(base_slot), encode_address(gauge)]);
    U256::from_be_bytes(gauge_encoded)
}

/// Pendle-specific slot calculation.
/// Uses uint128 encoding and different struct layout.
fn gauge_time_slot_pendle(gauge: Address, epoch: u64, base_slot: U256) -> U256 {
    let encoded_1 = keccak_abi_encode(&[encode_uint128(epoch as u128), encode_u256(base_slot)]);
    let struct_slot = U256::from_be_bytes(encoded_1) + U256::from(1u64);
    let encoded_2 = keccak_abi_encode(&[encode_address(gauge), encode_u256(struct_slot)]);
    U256::from_be_bytes(encoded_2)
}

///////////////////////////////////////////////
// USER VOTE SLOT CALCULATIONS
///////////////////////////////////////////////

/// Compute storage slots for user vote data based on protocol.
pub fn user_vote_slots(
    protocol: Protocol,
    account: Address,
    gauge: Address,
    last_vote_base_slot: U256,
    user_slope_base_slot: U256,
) -> Vec<SlotRequest> {
    let mut slots = Vec::new();

    // last_vote slot (not present for Pendle)
    // Note: Curve uses DEFAULT (post-Vyper-0.3) layout for last_user_vote mapping,
    // but pre-Vyper-0.3 layout for vote_user_slopes mapping
    if protocol != Protocol::Pendle {
        let last_vote_slot = match protocol {
            // All protocols use default slot calculation for last_user_vote
            Protocol::Curve
            | Protocol::Balancer
            | Protocol::Frax
            | Protocol::Fxn
            | Protocol::Yb
            | Protocol::Default => user_gauge_slot_default(account, gauge, last_vote_base_slot),
            Protocol::Pendle => unreachable!(),
        };
        slots.push(SlotRequest {
            label: "last_vote".to_string(),
            slot: last_vote_slot,
        });
    }

    // user_slope slot
    let vote_user_slope_slot = match protocol {
        Protocol::Curve => user_gauge_slot_pre_vyper03(account, gauge, user_slope_base_slot),
        Protocol::Pendle => user_gauge_slot_pendle(account, gauge, user_slope_base_slot),
        // Balancer, Frax, Fxn, Yb use Vyper 0.3+ default slot calculation
        Protocol::Balancer | Protocol::Frax | Protocol::Fxn | Protocol::Yb | Protocol::Default => {
            user_gauge_slot_default(account, gauge, user_slope_base_slot)
        }
    };

    slots.push(SlotRequest {
        label: "user_slope".to_string(),
        slot: vote_user_slope_slot,
    });

    // Additional slots (end, bias) with offsets from slope slot
    let additional_offsets: Vec<(u64, &str)> = match protocol {
        Protocol::Yb => vec![(1, "user_bias"), (3, "user_end")],
        Protocol::Pendle => vec![(1, "user_bias")],
        // Curve, Balancer, Frax, Fxn, Default: user_end is at slope + 2
        Protocol::Curve | Protocol::Balancer | Protocol::Frax | Protocol::Fxn | Protocol::Default => {
            vec![(2, "user_end")]
        }
    };

    for (offset, label) in additional_offsets {
        slots.push(SlotRequest {
            label: label.to_string(),
            slot: vote_user_slope_slot + U256::from(offset),
        });
    }

    slots
}

/// Default user/gauge slot calculation for Vyper 0.3+ contracts.
fn user_gauge_slot_default(account: Address, gauge: Address, base_slot: U256) -> U256 {
    let user_encoded = keccak_abi_encode(&[encode_u256(base_slot), encode_address(account)]);
    let final_hash = keccak_abi_encode(&[user_encoded, encode_address(gauge)]);
    U256::from_be_bytes(final_hash)
}

/// Pre-Vyper 0.3 user/gauge slot calculation (used by Curve for vote_user_slopes).
fn user_gauge_slot_pre_vyper03(account: Address, gauge: Address, base_slot: U256) -> U256 {
    let user_encoded = keccak_abi_encode(&[encode_u256(base_slot), encode_address(account)]);
    let intermediate = keccak_abi_encode(&[user_encoded, encode_address(gauge)]);
    let final_hash = keccak_abi_encode(&[intermediate]);
    U256::from_be_bytes(final_hash)
}

/// Pendle-specific user/gauge slot calculation.
fn user_gauge_slot_pendle(account: Address, gauge: Address, base_slot: U256) -> U256 {
    let encoded_1 = keccak_abi_encode(&[encode_address(account), encode_u256(base_slot)]);
    let struct_slot = U256::from_be_bytes(encoded_1) + U256::from(1u64);
    let encoded_2 = keccak_abi_encode(&[encode_address(gauge), encode_u256(struct_slot)]);
    U256::from_be_bytes(encoded_2)
}
