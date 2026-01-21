#![cfg_attr(target_os = "zkvm", no_main)]
// Allow dead_code when not compiling for zkvm, as the main entry point and its
// called functions are only used in the zkvm build.
#![cfg_attr(not(target_os = "zkvm"), allow(dead_code))]

#[cfg(target_os = "zkvm")]
sp1_zkvm::entrypoint!(main);

#[cfg(not(target_os = "zkvm"))]
fn main() {}

use alloy_primitives::{Address, B256, U256};
use alloy_rlp::{Decodable, RlpDecodable};
use alloy_sol_types::sol;
#[cfg(target_os = "zkvm")]
use alloy_sol_types::SolValue;
use eth_trie::{EthTrie, MemoryDB, Trie};
use ethereum_types::H256;
use sha3::{Digest, Keccak256};
#[cfg(target_os = "zkvm")]
use shared::Input;
use shared::{
    AccountRequest, AccountResult as SharedAccountResult, PointRequest,
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

#[cfg(target_os = "zkvm")]
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

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_rlp::Encodable;
    use eth_trie::{EthTrie, MemoryDB, Trie};

    // Known keccak256 hashes
    const KECCAK_EMPTY: &str = "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470";
    const KECCAK_HELLO: &str = "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8";

    // Test addresses and values
    const TEST_GAUGE: &str = "0x26f7786de3e6d9bd37fcf47be6f2bc455a21b74a";
    const TEST_ACCOUNT: &str = "0xfac2f11ba2577d5122dc1ec5301d35b16688251e";
    const TEST_EPOCH: u64 = 1730937600;

    /// Helper to create a valid Merkle proof for testing storage values.
    fn create_storage_trie_proof(slot: U256, value: U256) -> (B256, Vec<Vec<u8>>) {
        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = EthTrie::new(memdb.clone());

        let key = keccak256(&slot.to_be_bytes::<32>());

        // RLP encode the value
        let mut rlp_value = Vec::new();
        value.encode(&mut rlp_value);

        trie.insert(&key, &rlp_value).unwrap();
        let root = trie.root_hash().unwrap();
        let proof = trie.get_proof(&key).unwrap();

        (B256::from(root.0), proof)
    }

    /// Helper to create a valid account proof for testing.
    fn create_account_trie_proof(address: Address, storage_root: B256) -> (B256, Vec<Vec<u8>>) {
        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = EthTrie::new(memdb.clone());

        let key = keccak256(address.as_slice());

        // RLP encode account with nonce=0, balance=0, storage_root, code_hash=keccak256("")
        let nonce = U256::ZERO;
        let balance = U256::ZERO;
        let code_hash = B256::from_slice(&hex::decode(KECCAK_EMPTY).unwrap());

        let mut account_rlp = Vec::new();
        alloy_rlp::Header {
            list: true,
            payload_length: nonce.length()
                + balance.length()
                + storage_root.length()
                + code_hash.length(),
        }
        .encode(&mut account_rlp);
        nonce.encode(&mut account_rlp);
        balance.encode(&mut account_rlp);
        storage_root.encode(&mut account_rlp);
        code_hash.encode(&mut account_rlp);

        trie.insert(&key, &account_rlp).unwrap();
        let root = trie.root_hash().unwrap();
        let proof = trie.get_proof(&key).unwrap();

        (B256::from(root.0), proof)
    }

    // =========================================================================
    // Keccak256 Tests
    // =========================================================================

    #[test]
    fn test_keccak256_empty() {
        let hash = keccak256(&[]);
        let expected = hex::decode(KECCAK_EMPTY).unwrap();
        assert_eq!(hash.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_keccak256_hello() {
        let hash = keccak256(b"hello");
        let expected = hex::decode(KECCAK_HELLO).unwrap();
        assert_eq!(hash.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_keccak256_32_bytes() {
        // Test with 32 bytes of zeros (common pattern for slots)
        let input = [0u8; 32];
        let hash = keccak256(&input);
        // Verify hash is 32 bytes and non-zero
        assert_eq!(hash.len(), 32);
        assert_ne!(hash, [0u8; 32]);
    }

    #[test]
    fn test_keccak256_address() {
        let address = TEST_GAUGE.parse::<Address>().unwrap();
        let hash = keccak256(address.as_slice());
        // Verify hash is 32 bytes
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_keccak256_slot() {
        let slot = U256::from(123u64);
        let hash = keccak256(&slot.to_be_bytes::<32>());
        // Verify hash is 32 bytes
        assert_eq!(hash.len(), 32);
    }

    // =========================================================================
    // Account RLP Decoding Tests
    // =========================================================================

    #[test]
    fn test_account_decode_valid() {
        let nonce = U256::from(1u64);
        let balance = U256::from(1000u64);
        let storage_root = B256::from_slice(&hex::decode(KECCAK_EMPTY).unwrap());
        let code_hash = B256::from_slice(&hex::decode(KECCAK_EMPTY).unwrap());

        let mut rlp = Vec::new();
        alloy_rlp::Header {
            list: true,
            payload_length: nonce.length()
                + balance.length()
                + storage_root.length()
                + code_hash.length(),
        }
        .encode(&mut rlp);
        nonce.encode(&mut rlp);
        balance.encode(&mut rlp);
        storage_root.encode(&mut rlp);
        code_hash.encode(&mut rlp);

        let mut slice = rlp.as_slice();
        let account = Account::decode(&mut slice).unwrap();
        assert_eq!(account.storage_root, storage_root);
    }

    #[test]
    fn test_account_decode_extracts_storage_root() {
        let storage_root = B256::repeat_byte(0x42);
        let nonce = U256::ZERO;
        let balance = U256::ZERO;
        let code_hash = B256::from_slice(&hex::decode(KECCAK_EMPTY).unwrap());

        let mut rlp = Vec::new();
        alloy_rlp::Header {
            list: true,
            payload_length: nonce.length()
                + balance.length()
                + storage_root.length()
                + code_hash.length(),
        }
        .encode(&mut rlp);
        nonce.encode(&mut rlp);
        balance.encode(&mut rlp);
        storage_root.encode(&mut rlp);
        code_hash.encode(&mut rlp);

        let mut slice = rlp.as_slice();
        let account = Account::decode(&mut slice).unwrap();
        assert_eq!(account.storage_root, storage_root);
    }

    #[test]
    fn test_account_decode_zero_balance() {
        let nonce = U256::ZERO;
        let balance = U256::ZERO;
        let storage_root = B256::from_slice(&hex::decode(KECCAK_EMPTY).unwrap());
        let code_hash = B256::from_slice(&hex::decode(KECCAK_EMPTY).unwrap());

        let mut rlp = Vec::new();
        alloy_rlp::Header {
            list: true,
            payload_length: nonce.length()
                + balance.length()
                + storage_root.length()
                + code_hash.length(),
        }
        .encode(&mut rlp);
        nonce.encode(&mut rlp);
        balance.encode(&mut rlp);
        storage_root.encode(&mut rlp);
        code_hash.encode(&mut rlp);

        let mut slice = rlp.as_slice();
        let account = Account::decode(&mut slice);
        assert!(account.is_ok());
    }

    #[test]
    #[should_panic(expected = "Failed to decode account RLP")]
    fn test_account_decode_invalid_panics() {
        let invalid_rlp = vec![0xc0]; // Empty RLP list
        let mut slice = invalid_rlp.as_slice();
        let _ = Account::decode(&mut slice).expect("Failed to decode account RLP");
    }

    // =========================================================================
    // Verify Account Proof Tests
    // =========================================================================

    #[test]
    fn test_verify_account_proof_valid() {
        let address = TEST_GAUGE.parse::<Address>().unwrap();
        let expected_storage_root = B256::repeat_byte(0xab);

        let (state_root, proof) = create_account_trie_proof(address, expected_storage_root);
        let result = verify_account_proof(&state_root, address, &proof);

        assert_eq!(result, expected_storage_root);
    }

    #[test]
    fn test_verify_account_proof_address_hashing() {
        // Verify that different addresses produce different state roots
        let addr1 = TEST_GAUGE.parse::<Address>().unwrap();
        let addr2 = TEST_ACCOUNT.parse::<Address>().unwrap();
        let storage_root = B256::repeat_byte(0x11);

        let (root1, _) = create_account_trie_proof(addr1, storage_root);
        let (root2, _) = create_account_trie_proof(addr2, storage_root);

        // Different addresses should produce different state roots
        assert_ne!(root1, root2);
    }

    #[test]
    #[should_panic(expected = "Invalid state root or account proof")]
    fn test_verify_account_proof_invalid_panics() {
        let address = TEST_GAUGE.parse::<Address>().unwrap();
        let state_root = B256::repeat_byte(0xff);
        let invalid_proof: Vec<Vec<u8>> = vec![vec![0xc0]]; // Invalid proof

        let _ = verify_account_proof(&state_root, address, &invalid_proof);
    }

    #[test]
    #[should_panic(expected = "Invalid state root or account proof")]
    fn test_verify_account_proof_wrong_root_panics() {
        let address = TEST_GAUGE.parse::<Address>().unwrap();
        let storage_root = B256::repeat_byte(0xab);

        let (_, proof) = create_account_trie_proof(address, storage_root);
        let wrong_root = B256::repeat_byte(0x99);

        let _ = verify_account_proof(&wrong_root, address, &proof);
    }

    #[test]
    #[should_panic(expected = "Account not found in state trie")]
    fn test_verify_account_proof_missing_account_panics() {
        let address = TEST_GAUGE.parse::<Address>().unwrap();
        let other_address = TEST_ACCOUNT.parse::<Address>().unwrap();
        let storage_root = B256::repeat_byte(0xab);

        // Create proof for address but try to verify other_address
        let (state_root, proof) = create_account_trie_proof(address, storage_root);
        let _ = verify_account_proof(&state_root, other_address, &proof);
    }

    // =========================================================================
    // Verify Storage Proof Tests
    // =========================================================================

    #[test]
    fn test_verify_storage_proof_valid() {
        let slot = U256::from(42u64);
        let expected_value = U256::from(12345u64);

        let (storage_root, proof) = create_storage_trie_proof(slot, expected_value);
        let result = verify_storage_proof(&storage_root, slot, &proof);

        assert_eq!(result, expected_value);
    }

    #[test]
    fn test_verify_storage_proof_uninitialized_returns_zero() {
        // Create a trie with one slot, then query a different slot
        let slot1 = U256::from(1u64);
        let value1 = U256::from(100u64);
        let slot2 = U256::from(2u64);

        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = EthTrie::new(memdb.clone());

        let key1 = keccak256(&slot1.to_be_bytes::<32>());
        let mut rlp_value = Vec::new();
        value1.encode(&mut rlp_value);
        trie.insert(&key1, &rlp_value).unwrap();

        let root = B256::from(trie.root_hash().unwrap().0);
        let key2 = keccak256(&slot2.to_be_bytes::<32>());
        let proof = trie.get_proof(&key2).unwrap();

        let result = verify_storage_proof(&root, slot2, &proof);
        assert_eq!(result, U256::ZERO);
    }

    #[test]
    fn test_verify_storage_proof_slot_hashing() {
        // Verify that different slots produce different keys
        let slot1 = U256::from(1u64);
        let slot2 = U256::from(2u64);
        let value = U256::from(999u64);

        let (root1, _) = create_storage_trie_proof(slot1, value);
        let (root2, _) = create_storage_trie_proof(slot2, value);

        // Different slots should produce different roots
        assert_ne!(root1, root2);
    }

    #[test]
    #[should_panic(expected = "Invalid storage root or storage proof")]
    fn test_verify_storage_proof_invalid_panics() {
        let slot = U256::from(42u64);
        let storage_root = B256::repeat_byte(0xff);
        let invalid_proof: Vec<Vec<u8>> = vec![vec![0xc0]]; // Invalid proof

        let _ = verify_storage_proof(&storage_root, slot, &invalid_proof);
    }

    #[test]
    #[should_panic(expected = "Invalid storage root or storage proof")]
    fn test_verify_storage_proof_wrong_root_panics() {
        let slot = U256::from(42u64);
        let value = U256::from(12345u64);

        let (_, proof) = create_storage_trie_proof(slot, value);
        let wrong_root = B256::repeat_byte(0x99);

        let _ = verify_storage_proof(&wrong_root, slot, &proof);
    }

    #[test]
    fn test_verify_storage_proof_large_value() {
        let slot = U256::from(1u64);
        let large_value = U256::MAX;

        let (storage_root, proof) = create_storage_trie_proof(slot, large_value);
        let result = verify_storage_proof(&storage_root, slot, &proof);

        assert_eq!(result, large_value);
    }

    // =========================================================================
    // Process Point Requests Tests
    // =========================================================================

    #[test]
    fn test_process_point_requests_empty() {
        let state_root = B256::ZERO;
        let requests: Vec<PointRequest> = vec![];

        let results = process_point_requests(&state_root, TEST_EPOCH, &requests);

        assert!(results.is_empty());
    }

    #[test]
    fn test_process_point_requests_single() {
        let gauge = TEST_GAUGE.parse::<Address>().unwrap();
        let gauge_controller = TEST_ACCOUNT.parse::<Address>().unwrap();
        let bias_value = U256::from(1000u64);
        let bias_slot = U256::from(5u64);

        // Create storage proof for bias
        let (storage_root, bias_proof) = create_storage_trie_proof(bias_slot, bias_value);
        // Create account proof with storage root
        let (state_root, account_proof) = create_account_trie_proof(gauge_controller, storage_root);

        let request = PointRequest {
            gauge,
            gauge_controller,
            account_proof,
            bias_proof,
            bias_slot,
        };

        let results = process_point_requests(&state_root, TEST_EPOCH, &[request]);

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].gauge, gauge);
        assert_eq!(results[0].epoch, TEST_EPOCH);
        assert_eq!(results[0].bias, bias_value);
    }

    #[test]
    fn test_process_point_requests_preserves_epoch() {
        let gauge = TEST_GAUGE.parse::<Address>().unwrap();
        let gauge_controller = TEST_ACCOUNT.parse::<Address>().unwrap();
        let bias_value = U256::from(500u64);
        let bias_slot = U256::from(10u64);
        let custom_epoch = 1234567890u64;

        let (storage_root, bias_proof) = create_storage_trie_proof(bias_slot, bias_value);
        let (state_root, account_proof) = create_account_trie_proof(gauge_controller, storage_root);

        let request = PointRequest {
            gauge,
            gauge_controller,
            account_proof,
            bias_proof,
            bias_slot,
        };

        let results = process_point_requests(&state_root, custom_epoch, &[request]);

        assert_eq!(results[0].epoch, custom_epoch);
    }

    // =========================================================================
    // Process Account Requests Tests
    // =========================================================================

    #[test]
    fn test_process_account_requests_empty() {
        let state_root = B256::ZERO;
        let requests: Vec<AccountRequest> = vec![];

        let results = process_account_requests(&state_root, TEST_EPOCH, &requests);

        assert!(results.is_empty());
    }

    #[test]
    fn test_process_account_requests_with_last_vote() {
        let account = TEST_ACCOUNT.parse::<Address>().unwrap();
        let gauge = TEST_GAUGE.parse::<Address>().unwrap();
        let gauge_controller = Address::repeat_byte(0x11);

        let slope_value = U256::from(100u64);
        let end_value = U256::from(2000000000u64);
        let last_vote_value = U256::from(1730000000u64);

        let slope_slot = U256::from(1u64);
        let end_slot = U256::from(2u64);
        let last_vote_slot = U256::from(3u64);

        // Create a trie with all three values
        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = EthTrie::new(memdb.clone());

        for (slot, value) in [
            (slope_slot, slope_value),
            (end_slot, end_value),
            (last_vote_slot, last_vote_value),
        ] {
            let key = keccak256(&slot.to_be_bytes::<32>());
            let mut rlp_value = Vec::new();
            value.encode(&mut rlp_value);
            trie.insert(&key, &rlp_value).unwrap();
        }

        let storage_root = B256::from(trie.root_hash().unwrap().0);
        let slope_proof = trie
            .get_proof(&keccak256(&slope_slot.to_be_bytes::<32>()))
            .unwrap();
        let end_proof = trie
            .get_proof(&keccak256(&end_slot.to_be_bytes::<32>()))
            .unwrap();
        let last_vote_proof = trie
            .get_proof(&keccak256(&last_vote_slot.to_be_bytes::<32>()))
            .unwrap();

        let (state_root, account_proof) = create_account_trie_proof(gauge_controller, storage_root);

        let request = AccountRequest {
            account,
            gauge,
            gauge_controller,
            account_proof,
            slope_proof,
            end_proof,
            last_vote_proof: Some(last_vote_proof),
            slope_slot,
            end_slot,
            last_vote_slot: Some(last_vote_slot),
        };

        let results = process_account_requests(&state_root, TEST_EPOCH, &[request]);

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].slope, slope_value);
        assert_eq!(results[0].end, end_value);
        assert_eq!(results[0].last_vote, last_vote_value);
    }

    #[test]
    fn test_process_account_requests_without_last_vote() {
        let account = TEST_ACCOUNT.parse::<Address>().unwrap();
        let gauge = TEST_GAUGE.parse::<Address>().unwrap();
        let gauge_controller = Address::repeat_byte(0x22);

        let slope_value = U256::from(200u64);
        let end_value = U256::from(3000000000u64);

        let slope_slot = U256::from(10u64);
        let end_slot = U256::from(11u64);

        // Create a trie with slope and end values only
        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = EthTrie::new(memdb.clone());

        for (slot, value) in [(slope_slot, slope_value), (end_slot, end_value)] {
            let key = keccak256(&slot.to_be_bytes::<32>());
            let mut rlp_value = Vec::new();
            value.encode(&mut rlp_value);
            trie.insert(&key, &rlp_value).unwrap();
        }

        let storage_root = B256::from(trie.root_hash().unwrap().0);
        let slope_proof = trie
            .get_proof(&keccak256(&slope_slot.to_be_bytes::<32>()))
            .unwrap();
        let end_proof = trie
            .get_proof(&keccak256(&end_slot.to_be_bytes::<32>()))
            .unwrap();

        let (state_root, account_proof) = create_account_trie_proof(gauge_controller, storage_root);

        let request = AccountRequest {
            account,
            gauge,
            gauge_controller,
            account_proof,
            slope_proof,
            end_proof,
            last_vote_proof: None,
            slope_slot,
            end_slot,
            last_vote_slot: None,
        };

        let results = process_account_requests(&state_root, TEST_EPOCH, &[request]);

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].last_vote, U256::ZERO);
    }

    #[test]
    fn test_process_account_requests_preserves_fields() {
        let account = TEST_ACCOUNT.parse::<Address>().unwrap();
        let gauge = TEST_GAUGE.parse::<Address>().unwrap();
        let gauge_controller = Address::repeat_byte(0x33);
        let custom_epoch = 9876543210u64;

        let slope_value = U256::from(50u64);
        let end_value = U256::from(1500000000u64);
        let slope_slot = U256::from(20u64);
        let end_slot = U256::from(21u64);

        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = EthTrie::new(memdb.clone());

        for (slot, value) in [(slope_slot, slope_value), (end_slot, end_value)] {
            let key = keccak256(&slot.to_be_bytes::<32>());
            let mut rlp_value = Vec::new();
            value.encode(&mut rlp_value);
            trie.insert(&key, &rlp_value).unwrap();
        }

        let storage_root = B256::from(trie.root_hash().unwrap().0);
        let slope_proof = trie
            .get_proof(&keccak256(&slope_slot.to_be_bytes::<32>()))
            .unwrap();
        let end_proof = trie
            .get_proof(&keccak256(&end_slot.to_be_bytes::<32>()))
            .unwrap();

        let (state_root, account_proof) = create_account_trie_proof(gauge_controller, storage_root);

        let request = AccountRequest {
            account,
            gauge,
            gauge_controller,
            account_proof,
            slope_proof,
            end_proof,
            last_vote_proof: None,
            slope_slot,
            end_slot,
            last_vote_slot: None,
        };

        let results = process_account_requests(&state_root, custom_epoch, &[request]);

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].account, account);
        assert_eq!(results[0].gauge, gauge);
        assert_eq!(results[0].epoch, custom_epoch);
    }
}
