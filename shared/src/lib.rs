use alloy_primitives::{Address, B256, U256};
use serde::{Deserialize, Serialize};

///////////////////////////////////////////////////////////////////////////////
// INPUT TYPES (Host → Guest)
///////////////////////////////////////////////////////////////////////////////

/// The input data passed to the ZKVM.
/// Contains a state root and grouped requests for point data and account data.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Input {
    /// The trusted state root of the block.
    pub state_root: B256,
    /// The epoch (week-aligned timestamp) this proof is for.
    pub epoch: u64,
    /// Requests for gauge point data (total votes per gauge).
    pub point_requests: Vec<PointRequest>,
    /// Requests for account voting data (user votes per gauge).
    pub account_requests: Vec<AccountRequest>,
}

/// A request to verify gauge point data (points_weight[gauge][epoch]).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PointRequest {
    /// The gauge address.
    pub gauge: Address,
    /// The gauge controller contract address.
    pub gauge_controller: Address,
    /// Merkle proof from state root to gauge controller account.
    pub account_proof: Vec<Vec<u8>>,
    /// Merkle proof from storage root to bias slot.
    pub bias_proof: Vec<Vec<u8>>,
    /// The storage slot for points_weight[gauge][epoch].bias.
    pub bias_slot: U256,
}

/// A request to verify account voting data (vote_user_slopes, last_user_vote).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AccountRequest {
    /// The voter account address.
    pub account: Address,
    /// The gauge address.
    pub gauge: Address,
    /// The gauge controller contract address.
    pub gauge_controller: Address,
    /// Merkle proof from state root to gauge controller account.
    pub account_proof: Vec<Vec<u8>>,
    /// Merkle proof from storage root to slope slot.
    pub slope_proof: Vec<Vec<u8>>,
    /// Merkle proof from storage root to end slot.
    pub end_proof: Vec<Vec<u8>>,
    /// Merkle proof from storage root to last_vote slot (None for Pendle).
    pub last_vote_proof: Option<Vec<Vec<u8>>>,
    /// The storage slot for vote_user_slopes[account][gauge].slope.
    pub slope_slot: U256,
    /// The storage slot for vote_user_slopes[account][gauge].end.
    pub end_slot: U256,
    /// The storage slot for last_user_vote[account][gauge] (None for Pendle).
    pub last_vote_slot: Option<U256>,
}

///////////////////////////////////////////////////////////////////////////////
// OUTPUT TYPES (Guest → Host, committed as public values)
///////////////////////////////////////////////////////////////////////////////

/// The public output committed by the ZKVM.
/// Contains verified point data and account data grouped by type.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Output {
    /// The state root that was verified against.
    pub state_root: B256,
    /// The epoch this proof is for.
    pub epoch: u64,
    /// Verified gauge point data.
    pub point_results: Vec<PointResult>,
    /// Verified account voting data.
    pub account_results: Vec<AccountResult>,
}

/// Verified gauge point data (points_weight[gauge][epoch]).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct PointResult {
    /// The gauge address.
    pub gauge: Address,
    /// The epoch for this point data.
    pub epoch: u64,
    /// The bias (total votes) for this gauge at this epoch.
    pub bias: U256,
}

/// Verified account voting data (vote_user_slopes, last_user_vote).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct AccountResult {
    /// The voter account address.
    pub account: Address,
    /// The gauge address.
    pub gauge: Address,
    /// The epoch for this account data.
    pub epoch: u64,
    /// The voting slope (decay rate).
    pub slope: U256,
    /// The epoch when the vote expires.
    pub end: U256,
    /// The last vote timestamp (0 for Pendle which doesn't have this).
    pub last_vote: U256,
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test addresses
    const TEST_GAUGE: &str = "0x26f7786de3e6d9bd37fcf47be6f2bc455a21b74a";
    const TEST_ACCOUNT: &str = "0xfac2f11ba2577d5122dc1ec5301d35b16688251e";
    const TEST_STATE_ROOT: &str = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    const TEST_EPOCH: u64 = 1730937600;

    // =========================================================================
    // Input Serialization Tests
    // =========================================================================

    #[test]
    fn test_input_serialization_roundtrip() {
        let input = Input {
            state_root: TEST_STATE_ROOT.parse().unwrap(),
            epoch: TEST_EPOCH,
            point_requests: vec![],
            account_requests: vec![],
        };

        let json = serde_json::to_string(&input).unwrap();
        let deserialized: Input = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.state_root, input.state_root);
        assert_eq!(deserialized.epoch, input.epoch);
        assert!(deserialized.point_requests.is_empty());
        assert!(deserialized.account_requests.is_empty());
    }

    #[test]
    fn test_input_empty_requests() {
        let input = Input {
            state_root: B256::ZERO,
            epoch: 0,
            point_requests: vec![],
            account_requests: vec![],
        };

        let json = serde_json::to_string(&input).unwrap();
        let deserialized: Input = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.state_root, B256::ZERO);
        assert_eq!(deserialized.epoch, 0);
    }

    // =========================================================================
    // PointRequest Serialization Tests
    // =========================================================================

    #[test]
    fn test_point_request_serialization() {
        let request = PointRequest {
            gauge: TEST_GAUGE.parse().unwrap(),
            gauge_controller: TEST_ACCOUNT.parse().unwrap(),
            account_proof: vec![vec![0x01, 0x02], vec![0x03, 0x04]],
            bias_proof: vec![vec![0x05, 0x06]],
            bias_slot: U256::from(42u64),
        };

        let json = serde_json::to_string(&request).unwrap();
        let deserialized: PointRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.gauge, request.gauge);
        assert_eq!(deserialized.gauge_controller, request.gauge_controller);
        assert_eq!(deserialized.account_proof, request.account_proof);
        assert_eq!(deserialized.bias_proof, request.bias_proof);
        assert_eq!(deserialized.bias_slot, request.bias_slot);
    }

    // =========================================================================
    // AccountRequest Serialization Tests
    // =========================================================================

    #[test]
    fn test_account_request_serialization() {
        let request = AccountRequest {
            account: TEST_ACCOUNT.parse().unwrap(),
            gauge: TEST_GAUGE.parse().unwrap(),
            gauge_controller: TEST_ACCOUNT.parse().unwrap(),
            account_proof: vec![vec![0x10, 0x20]],
            slope_proof: vec![vec![0x30, 0x40]],
            end_proof: vec![vec![0x50, 0x60]],
            last_vote_proof: Some(vec![vec![0x70, 0x80]]),
            slope_slot: U256::from(100u64),
            end_slot: U256::from(101u64),
            last_vote_slot: Some(U256::from(102u64)),
        };

        let json = serde_json::to_string(&request).unwrap();
        let deserialized: AccountRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.account, request.account);
        assert_eq!(deserialized.gauge, request.gauge);
        assert_eq!(deserialized.slope_slot, request.slope_slot);
        assert_eq!(deserialized.end_slot, request.end_slot);
        assert_eq!(deserialized.last_vote_slot, request.last_vote_slot);
    }

    #[test]
    fn test_account_request_optional_last_vote() {
        let request = AccountRequest {
            account: TEST_ACCOUNT.parse().unwrap(),
            gauge: TEST_GAUGE.parse().unwrap(),
            gauge_controller: TEST_ACCOUNT.parse().unwrap(),
            account_proof: vec![],
            slope_proof: vec![],
            end_proof: vec![],
            last_vote_proof: None,
            slope_slot: U256::ZERO,
            end_slot: U256::ZERO,
            last_vote_slot: None,
        };

        let json = serde_json::to_string(&request).unwrap();
        let deserialized: AccountRequest = serde_json::from_str(&json).unwrap();

        assert!(deserialized.last_vote_proof.is_none());
        assert!(deserialized.last_vote_slot.is_none());
    }

    // =========================================================================
    // PointResult Serialization Tests
    // =========================================================================

    #[test]
    fn test_point_result_serialization() {
        let result = PointResult {
            gauge: TEST_GAUGE.parse().unwrap(),
            epoch: TEST_EPOCH,
            bias: U256::from(1000000u64),
        };

        let json = serde_json::to_string(&result).unwrap();
        let deserialized: PointResult = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.gauge, result.gauge);
        assert_eq!(deserialized.epoch, result.epoch);
        assert_eq!(deserialized.bias, result.bias);
    }

    // =========================================================================
    // AccountResult Serialization Tests
    // =========================================================================

    #[test]
    fn test_account_result_serialization() {
        let result = AccountResult {
            account: TEST_ACCOUNT.parse().unwrap(),
            gauge: TEST_GAUGE.parse().unwrap(),
            epoch: TEST_EPOCH,
            slope: U256::from(500u64),
            end: U256::from(2000000000u64),
            last_vote: U256::from(1700000000u64),
        };

        let json = serde_json::to_string(&result).unwrap();
        let deserialized: AccountResult = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized, result);
    }

    // =========================================================================
    // Output Serialization Tests
    // =========================================================================

    #[test]
    fn test_output_serialization() {
        let output = Output {
            state_root: TEST_STATE_ROOT.parse().unwrap(),
            epoch: TEST_EPOCH,
            point_results: vec![PointResult {
                gauge: TEST_GAUGE.parse().unwrap(),
                epoch: TEST_EPOCH,
                bias: U256::from(999u64),
            }],
            account_results: vec![AccountResult {
                account: TEST_ACCOUNT.parse().unwrap(),
                gauge: TEST_GAUGE.parse().unwrap(),
                epoch: TEST_EPOCH,
                slope: U256::from(100u64),
                end: U256::from(1800000000u64),
                last_vote: U256::ZERO,
            }],
        };

        let json = serde_json::to_string(&output).unwrap();
        let deserialized: Output = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.state_root, output.state_root);
        assert_eq!(deserialized.epoch, output.epoch);
        assert_eq!(deserialized.point_results.len(), 1);
        assert_eq!(deserialized.account_results.len(), 1);
    }

    // =========================================================================
    // Address and B256 Serialization Tests
    // =========================================================================

    #[test]
    fn test_address_serialization() {
        let address: Address = TEST_GAUGE.parse().unwrap();
        let json = serde_json::to_string(&address).unwrap();
        let deserialized: Address = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized, address);
        // Verify JSON contains hex format
        assert!(json.contains("0x"));
    }

    #[test]
    fn test_b256_serialization() {
        let hash: B256 = TEST_STATE_ROOT.parse().unwrap();
        let json = serde_json::to_string(&hash).unwrap();
        let deserialized: B256 = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized, hash);
        // Verify JSON contains hex format
        assert!(json.contains("0x"));
    }
}
