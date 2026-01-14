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
#[derive(Serialize, Deserialize, Debug, Clone)]
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
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PointResult {
    /// The gauge address.
    pub gauge: Address,
    /// The epoch for this point data.
    pub epoch: u64,
    /// The bias (total votes) for this gauge at this epoch.
    pub bias: U256,
}

/// Verified account voting data (vote_user_slopes, last_user_vote).
#[derive(Serialize, Deserialize, Debug, Clone)]
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
