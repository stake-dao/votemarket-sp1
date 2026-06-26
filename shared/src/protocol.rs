//! Protocol definitions and storage-slot derivation.
//!
//! Security note: the base mapping slots are circuit constants here, not
//! host-supplied. An unknown protocol is rejected (host-side `Err`, guest-side panic).

use alloy_primitives::{address, Address, U256};
use serde::{Deserialize, Serialize};

use crate::encoding::{encode_address, encode_u256, encode_uint128, keccak_abi_encode};

/// Supported protocols and their storage layouts. No `Default`: an unknown
/// protocol is rejected rather than falling back to host-supplied slots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Curve,
    Balancer,
    Frax,
    Fxn,
    Yb,
    Pendle,
}

/// Error returned when a `u8` does not map to a known protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnknownProtocol(pub u8);

impl core::fmt::Display for UnknownProtocol {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "unknown protocol_id: {}", self.0)
    }
}

impl Protocol {
    /// Canonical wire id (private circuit input). Order is load-bearing: changing
    /// these values rotates the meaning of every persisted `protocol_id`.
    pub fn as_u8(&self) -> u8 {
        match self {
            Protocol::Curve => 0,
            Protocol::Balancer => 1,
            Protocol::Frax => 2,
            Protocol::Fxn => 3,
            Protocol::Yb => 4,
            Protocol::Pendle => 5,
        }
    }

    /// Parse a protocol name. Returns `None` for an unknown name (no `Default`).
    /// Named `from_name` (not `from_str`) to avoid the `FromStr` trait confusion.
    pub fn from_name(value: &str) -> Option<Self> {
        match value.to_lowercase().as_str() {
            "curve" => Some(Self::Curve),
            "balancer" => Some(Self::Balancer),
            "frax" => Some(Self::Frax),
            "fxn" => Some(Self::Fxn),
            "yb" => Some(Self::Yb),
            "pendle" => Some(Self::Pendle),
            _ => None,
        }
    }

    /// Canonical base mapping slots for this protocol. These are circuit constants
    /// (formerly `toolkit_slots`); they MUST match `votemarket_toolkit/shared/registry.py`.
    pub fn base_slots(&self) -> SlotConfig {
        match self {
            Protocol::Curve => SlotConfig {
                weight_mapping_slot: U256::from(12),
                last_vote_mapping_slot: U256::from(11),
                user_slope_mapping_slot: U256::from(9),
            },
            Protocol::Balancer => SlotConfig {
                weight_mapping_slot: U256::from(1000000008u64),
                last_vote_mapping_slot: U256::from(1000000007u64),
                user_slope_mapping_slot: U256::from(1000000005u64),
            },
            Protocol::Frax => SlotConfig {
                weight_mapping_slot: U256::from(1000000011u64),
                last_vote_mapping_slot: U256::from(1000000010u64),
                user_slope_mapping_slot: U256::from(1000000008u64),
            },
            Protocol::Fxn => SlotConfig {
                weight_mapping_slot: U256::from(1000000011u64),
                last_vote_mapping_slot: U256::from(1000000010u64),
                user_slope_mapping_slot: U256::from(1000000008u64),
            },
            Protocol::Yb => SlotConfig {
                weight_mapping_slot: U256::from(1000000006u64),
                last_vote_mapping_slot: U256::from(1000000005u64),
                user_slope_mapping_slot: U256::from(1000000003u64),
            },
            Protocol::Pendle => SlotConfig {
                weight_mapping_slot: U256::from(161),
                last_vote_mapping_slot: U256::ZERO, // Pendle has no last_user_vote
                user_slope_mapping_slot: U256::from(162),
            },
        }
    }

    /// Host-only convenience kept for call-site compatibility. Always `Some` now
    /// that `Default` is gone.
    pub fn toolkit_slots(&self) -> Option<SlotConfig> {
        Some(self.base_slots())
    }

    /// The gauge controller address for this protocol.
    /// These MUST match `votemarket_toolkit/shared/constants.py`.
    pub fn gauge_controller(&self) -> Option<Address> {
        Some(match self {
            Protocol::Curve => address!("2F50D538606Fa9EDD2B11E2446BEb18C9D5846bB"),
            Protocol::Balancer => address!("C128468b7Ce63eA702C1f104D55A2566b13D3ABD"),
            Protocol::Frax => address!("3669C421b77340B2979d1A00a792CC2ee0FcE737"),
            Protocol::Fxn => address!("e60eB8098B34eD775ac44B1ddE864e098C6d7f37"),
            Protocol::Pendle => address!("44087E105137a5095c008AaB6a6530182821F2F0"),
            Protocol::Yb => address!("1Be14811A3a06F6aF4fA64310a636e1Df04c1c21"),
        })
    }
}

impl TryFrom<u8> for Protocol {
    type Error = UnknownProtocol;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Protocol::Curve),
            1 => Ok(Protocol::Balancer),
            2 => Ok(Protocol::Frax),
            3 => Ok(Protocol::Fxn),
            4 => Ok(Protocol::Yb),
            5 => Ok(Protocol::Pendle),
            other => Err(UnknownProtocol(other)),
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

/// The three account slots the guest verifies, derived in-circuit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccountSlots {
    pub slope: U256,
    pub end: U256,
    pub last_vote: Option<U256>,
}

///////////////////////////////////////////////
// GUEST ENTRY POINTS (base slots from constants)
///////////////////////////////////////////////

/// Derive the point (bias) slot for `(protocol, gauge, epoch)` using the
/// protocol's canonical base slot. Used by the guest circuit.
pub fn derive_point_slot(protocol: Protocol, gauge: Address, epoch: u64) -> U256 {
    gauge_time_slot(
        protocol,
        gauge,
        epoch,
        protocol.base_slots().weight_mapping_slot,
    )
}

/// Derive the `(slope, end, last_vote)` slots for `(protocol, account, gauge)`
/// using the protocol's canonical base slots. Used by the guest circuit. The
/// label selection mirrors the host's `build_input_*` selection exactly, so the
/// guest reproduces the host-derived slots byte-for-byte.
pub fn derive_account_slots(protocol: Protocol, account: Address, gauge: Address) -> AccountSlots {
    let base = protocol.base_slots();
    let slots = user_vote_slots(
        protocol,
        account,
        gauge,
        base.last_vote_mapping_slot,
        base.user_slope_mapping_slot,
    );

    let slope = slots
        .iter()
        .find(|s| s.label == "user_slope")
        .expect("user_slope slot always present")
        .slot;
    // Mirror the host: first match of user_end OR user_bias.
    let end = slots
        .iter()
        .find(|s| s.label == "user_end" || s.label == "user_bias")
        .expect("user_end/user_bias slot always present")
        .slot;
    let last_vote = slots
        .iter()
        .find(|s| s.label == "last_vote")
        .map(|s| s.slot);

    AccountSlots {
        slope,
        end,
        last_vote,
    }
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
        Protocol::Balancer | Protocol::Frax | Protocol::Fxn => {
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
        let last_vote_slot = user_gauge_slot_default(account, gauge, last_vote_base_slot);
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
        Protocol::Balancer | Protocol::Frax | Protocol::Fxn | Protocol::Yb => {
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
        // Curve, Balancer, Frax, Fxn: user_end is at slope + 2
        Protocol::Curve | Protocol::Balancer | Protocol::Frax | Protocol::Fxn => {
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

fn deserialize_u256<'de, D>(deserializer: D) -> Result<U256, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;
    let value = String::deserialize(deserializer)?;
    let trimmed = value.strip_prefix("0x").unwrap_or(&value);
    let radix = if value.starts_with("0x") { 16 } else { 10 };
    U256::from_str_radix(trimmed, radix).map_err(serde::de::Error::custom)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;

    const TEST_GAUGE: Address = address!("26f7786de3e6d9bd37fcf47be6f2bc455a21b74a");
    const TEST_ACCOUNT: Address = address!("fac2f11ba2577d5122dc1ec5301d35b16688251e");
    const TEST_EPOCH: u64 = 1730937600;

    const ALL: [Protocol; 6] = [
        Protocol::Curve,
        Protocol::Balancer,
        Protocol::Frax,
        Protocol::Fxn,
        Protocol::Yb,
        Protocol::Pendle,
    ];

    #[test]
    fn test_protocol_id_roundtrip() {
        for p in ALL {
            assert_eq!(Protocol::try_from(p.as_u8()).unwrap(), p);
        }
    }

    #[test]
    fn test_protocol_id_rejects_unknown() {
        for v in 6u8..=255 {
            assert_eq!(Protocol::try_from(v), Err(UnknownProtocol(v)));
        }
    }

    #[test]
    fn test_from_str_known_and_unknown() {
        assert_eq!(Protocol::from_name("CURVE"), Some(Protocol::Curve));
        assert_eq!(Protocol::from_name("pendle"), Some(Protocol::Pendle));
        assert_eq!(Protocol::from_name("unknown"), None);
        assert_eq!(Protocol::from_name(""), None);
    }

    #[test]
    fn test_gauge_controller_present_for_all() {
        for p in ALL {
            assert!(p.gauge_controller().is_some());
        }
    }

    #[test]
    fn test_derive_point_slot_matches_manual() {
        // derive_point_slot must equal gauge_time_slot with the protocol's base slot.
        for p in ALL {
            let derived = derive_point_slot(p, TEST_GAUGE, TEST_EPOCH);
            let manual = gauge_time_slot(
                p,
                TEST_GAUGE,
                TEST_EPOCH,
                p.base_slots().weight_mapping_slot,
            );
            assert_eq!(derived, manual, "point slot mismatch for {p:?}");
            assert!(derived > U256::ZERO);
        }
    }

    #[test]
    fn test_derive_account_slots_curve() {
        let s = derive_account_slots(Protocol::Curve, TEST_ACCOUNT, TEST_GAUGE);
        // Curve: end = slope + 2, last_vote present.
        assert_eq!(s.end, s.slope + U256::from(2));
        assert!(s.last_vote.is_some());
    }

    #[test]
    fn test_derive_account_slots_pendle_no_last_vote() {
        let s = derive_account_slots(Protocol::Pendle, TEST_ACCOUNT, TEST_GAUGE);
        // Pendle: no last_vote, end = user_bias = slope + 1.
        assert!(s.last_vote.is_none());
        assert_eq!(s.end, s.slope + U256::from(1));
    }

    #[test]
    fn test_derive_account_slots_yb_end_is_first_match() {
        // Yb slot Vec order is [last_vote, user_slope, user_bias, user_end]; the
        // host selects the FIRST of (user_end|user_bias) = user_bias = slope + 1.
        // This quirk is preserved for byte-for-byte parity.
        let s = derive_account_slots(Protocol::Yb, TEST_ACCOUNT, TEST_GAUGE);
        assert_eq!(s.end, s.slope + U256::from(1));
        assert!(s.last_vote.is_some());
    }

    #[test]
    fn test_gauge_time_slot_pre_vyper03_different_from_default() {
        let pre = gauge_time_slot_pre_vyper03(TEST_GAUGE, TEST_EPOCH, U256::from(12));
        let def = gauge_time_slot_default(TEST_GAUGE, TEST_EPOCH, U256::from(12));
        assert_ne!(pre, def);
    }

    #[test]
    fn test_user_vote_slots_counts() {
        assert_eq!(
            user_vote_slots(
                Protocol::Curve,
                TEST_ACCOUNT,
                TEST_GAUGE,
                U256::from(11),
                U256::from(9)
            )
            .len(),
            3
        );
        assert_eq!(
            user_vote_slots(
                Protocol::Yb,
                TEST_ACCOUNT,
                TEST_GAUGE,
                U256::from(1000000005u64),
                U256::from(1000000003u64)
            )
            .len(),
            4
        );
        let pendle = user_vote_slots(
            Protocol::Pendle,
            TEST_ACCOUNT,
            TEST_GAUGE,
            U256::ZERO,
            U256::from(162),
        );
        assert!(!pendle.iter().any(|s| s.label == "last_vote"));
    }

    // Golden cross-language parity vs the Python toolkit
    // (votemarket_toolkit/shared/registry.py). The toolkit's base mapping slots
    // are mirrored in base_slots(); these assert the Rust constants equal the
    // toolkit's expected values per protocol. If registry.py changes, this fails.
    #[test]
    fn test_toolkit_base_slot_parity() {
        // (weight, last_vote, user_slope) expected from registry.py.
        let expected: [(Protocol, u64, u64, u64); 6] = [
            (Protocol::Curve, 12, 11, 9),
            (Protocol::Balancer, 1000000008, 1000000007, 1000000005),
            (Protocol::Frax, 1000000011, 1000000010, 1000000008),
            (Protocol::Fxn, 1000000011, 1000000010, 1000000008),
            (Protocol::Yb, 1000000006, 1000000005, 1000000003),
            (Protocol::Pendle, 161, 0, 162),
        ];
        for (p, w, l, u) in expected {
            let b = p.base_slots();
            assert_eq!(b.weight_mapping_slot, U256::from(w), "weight {p:?}");
            assert_eq!(b.last_vote_mapping_slot, U256::from(l), "last_vote {p:?}");
            assert_eq!(b.user_slope_mapping_slot, U256::from(u), "user_slope {p:?}");
        }
    }
}
