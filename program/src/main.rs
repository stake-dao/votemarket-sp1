#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_primitives::{Address, B256, U256};
use alloy_rlp::{Decodable, RlpDecodable};
use eth_trie::{EthTrie, MemoryDB, Trie};
use ethereum_types::H256;
use sha3::{Digest, Keccak256};
use shared::{AccountRequest, AccountResult, Input, Output, PointRequest, PointResult};
use std::sync::Arc;

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

    let point_results = process_point_requests(&input.state_root, input.epoch, &input.point_requests);
    let account_results = process_account_requests(&input.state_root, input.epoch, &input.account_requests);

    let output = Output {
        state_root: input.state_root,
        epoch: input.epoch,
        point_results,
        account_results,
    };
    sp1_zkvm::io::commit(&output);
}

/// Process all point requests (gauge total votes) and extract gauge bias values.
fn process_point_requests(
    state_root: &B256,
    epoch: u64,
    requests: &[PointRequest],
) -> Vec<PointResult> {
    requests
        .iter()
        .map(|req| {
            // Verify account proof to get storage root
            let storage_root =
                verify_account_proof(state_root, req.gauge_controller, &req.account_proof);

            // Verify storage proof to get bias value
            let bias = verify_storage_proof(&storage_root, req.bias_slot, &req.bias_proof);

            PointResult {
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
) -> Vec<AccountResult> {
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

            AccountResult {
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
