#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_primitives::{Address, B256, U256};
use alloy_rlp::{Decodable, RlpDecodable};
use alloy_sol_types::{sol, SolValue};
use eth_trie::{EthTrie, MemoryDB, Trie};
use ethereum_types::H256;
use sha3::{Digest, Keccak256};
use shared::{
    AccountRequest, AccountResult as SharedAccountResult, Input, PointRequest,
    PointResult as SharedPointResult,
};
use std::sync::Arc;

// Define Solidity-compatible types for ABI encoding.
// These match the structs in ZKVerifier.sol for direct on-chain decoding.
sol! {
    /// Verified gauge point data (points_weight[gauge][epoch]).
    struct PointResult {
        address gauge;
        uint256 epoch;
        uint256 bias;
    }

    /// Verified account voting data (vote_user_slopes, last_user_vote).
    struct AccountResult {
        address account;
        address gauge;
        uint256 epoch;
        uint256 slope;
        uint256 end;
        uint256 lastVote;
    }

    /// Public values struct committed by the circuit.
    /// This is the root type that gets ABI-encoded and committed.
    struct PublicValues {
        bytes32 stateRoot;
        uint256 epoch;
        PointResult[] pointResults;
        AccountResult[] accountResults;
    }
}

/// RLP-decoded Ethereum account structure.
/// Fields prefixed with `_` are required for RLP decoding but not used by the circuit.
#[derive(RlpDecodable)]
struct Account {
    _nonce: U256,
    _balance: U256,
    storage_root: B256,
    _code_hash: B256,
}

pub fn main() {
    let input = sp1_zkvm::io::read::<Input>();

    let point_results =
        process_point_requests(&input.state_root, input.epoch, &input.point_requests);
    let account_results =
        process_account_requests(&input.state_root, input.epoch, &input.account_requests);

    // Convert to Solidity-compatible types for ABI encoding.
    // Following SP1's recommended pattern: abi_encode() + commit_slice()
    let sol_point_results: Vec<PointResult> = point_results
        .iter()
        .map(|p| PointResult {
            gauge: p.gauge,
            epoch: U256::from(p.epoch),
            bias: p.bias,
        })
        .collect();

    let sol_account_results: Vec<AccountResult> = account_results
        .iter()
        .map(|a| AccountResult {
            account: a.account,
            gauge: a.gauge,
            epoch: U256::from(a.epoch),
            slope: a.slope,
            end: a.end,
            lastVote: a.last_vote,
        })
        .collect();

    // Create the public values struct and ABI-encode it.
    let public_values = PublicValues {
        stateRoot: input.state_root,
        epoch: U256::from(input.epoch),
        pointResults: sol_point_results,
        accountResults: sol_account_results,
    };

    // Commit the ABI-encoded struct directly.
    // The resulting public_values_raw can be decoded in Solidity with:
    // abi.decode(publicValues, (PublicValues))
    sp1_zkvm::io::commit_slice(&PublicValues::abi_encode(&public_values));
}

/// Process all point requests (gauge total votes) and extract gauge bias values.
fn process_point_requests(
    state_root: &B256,
    epoch: u64,
    requests: &[PointRequest],
) -> Vec<SharedPointResult> {
    requests
        .iter()
        .map(|req| {
            // Verify account proof to get storage root
            let storage_root =
                verify_account_proof(state_root, req.gauge_controller, &req.account_proof);

            // Verify storage proof to get bias value
            let bias = verify_storage_proof(&storage_root, req.bias_slot, &req.bias_proof);

            SharedPointResult {
                gauge: req.gauge,
                epoch,
                bias,
            }
        })
        .collect()
}

/// Process all account requests and extract voting data.
fn process_account_requests(
    state_root: &B256,
    epoch: u64,
    requests: &[AccountRequest],
) -> Vec<SharedAccountResult> {
    requests
        .iter()
        .map(|req| {
            // Verify account proof to get storage root
            let storage_root =
                verify_account_proof(state_root, req.gauge_controller, &req.account_proof);

            // Verify storage proof to get the slope and end values
            let slope = verify_storage_proof(&storage_root, req.slope_slot, &req.slope_proof);
            let end = verify_storage_proof(&storage_root, req.end_slot, &req.end_proof);

            // Verify last_vote proof if present (not present for Pendle)
            let last_vote = match (&req.last_vote_slot, &req.last_vote_proof) {
                (Some(slot), Some(proof)) => verify_storage_proof(&storage_root, *slot, proof),
                _ => U256::ZERO,
            };

            SharedAccountResult {
                account: req.account,
                gauge: req.gauge,
                epoch,
                slope,
                end,
                last_vote,
            }
        })
        .collect()
}

/// Verify an account proof against the state root and extract the storage root.
///
/// # Arguments
/// * `state_root` - The block's state root
/// * `address` - The account address to verify
/// * `proof` - The Merkle-Patricia proof nodes
///
/// # Returns
/// The storage root of the verified account
///
/// # Panics
/// If the proof is invalid or the account doesn't exist
fn verify_account_proof(state_root: &B256, address: Address, proof: &[Vec<u8>]) -> B256 {
    let root = H256::from(state_root.0);
    let key = keccak256(address.as_slice());
    let trie = EthTrie::new(Arc::new(MemoryDB::new(true)));

    let value = trie
        .verify_proof(root, &key, proof.to_vec())
        .expect("Invalid state root or account proof")
        .expect("Account not found in state trie");

    let mut slice = value.as_slice();
    let account = Account::decode(&mut slice).expect("Failed to decode account RLP");
    account.storage_root
}

/// Verify a storage proof against the storage root and extract the value.
///
/// # Arguments
/// * `storage_root` - The account's storage root
/// * `slot` - The storage slot to verify
/// * `proof` - The Merkle-Patricia proof nodes
///
/// # Returns
/// The value at the storage slot (U256::ZERO if uninitialized)
///
/// # Panics
/// If the proof is invalid
fn verify_storage_proof(storage_root: &B256, slot: U256, proof: &[Vec<u8>]) -> U256 {
    let root = H256::from(storage_root.0);
    let key = keccak256(&slot.to_be_bytes::<32>());
    let trie = EthTrie::new(Arc::new(MemoryDB::new(true)));

    let value = trie
        .verify_proof(root, &key, proof.to_vec())
        .expect("Invalid storage root or storage proof");

    match value {
        Some(value) => {
            let mut slice = value.as_slice();
            U256::decode(&mut slice).expect("Failed to decode storage value RLP")
        }
        None => U256::ZERO, // Uninitialized slot returns zero
    }
}

/// Compute Keccak256 hash of the input data.
fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    hasher.finalize().into()
}
