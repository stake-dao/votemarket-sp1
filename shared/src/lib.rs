use alloy_primitives::{Address, B256, U256};
use serde::{Deserialize, Serialize};

/// The input data passed to the ZKVM.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Input {
    /// The trusted state root of the block.
    pub state_root: B256,
    /// The list of storage slots to verify.
    pub proofs: Vec<StorageProofRequest>,
}

/// A single request to verify a storage slot.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StorageProofRequest {
    pub account: Address,
    pub slot: U256,
    pub account_proof: Vec<Vec<u8>>,
    pub storage_proof: Vec<Vec<u8>>,
}

/// The public output committed by the ZKVM.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Output {
    pub state_root: B256,
    pub results: Vec<StorageResult>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StorageResult {
    pub account: Address,
    pub slot: U256,
    pub value: U256,
}