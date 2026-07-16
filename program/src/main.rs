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
use shared::protocol::{derive_account_slots, derive_point_slot, Protocol};
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
        uint8 protocolId;
        address gaugeController;
    }

    /// Verified account voting data (vote_user_slopes, last_user_vote).
    struct AccountResult {
        address account;
        address gauge;
        uint256 epoch;
        uint256 slope;
        uint256 end;
        uint256 lastVote;
        uint8 protocolId;
        address gaugeController;
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
            protocolId: p.protocol_id,
            gaugeController: p.gauge_controller,
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
            protocolId: a.protocol_id,
            gaugeController: a.gauge_controller,
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
            // Reject unknown protocol ids (fail-closed: panic => unprovable proof).
            let protocol = Protocol::try_from(req.protocol_id)
                .unwrap_or_else(|e| panic!("invalid protocol_id: {e}"));

            // Verify account proof to get storage root
            let storage_root =
                verify_account_proof(state_root, req.gauge_controller, &req.account_proof);

            // Derive the canonical bias slot in-circuit and verify the value lives there.
            let bias_slot = derive_point_slot(protocol, req.gauge, epoch);
            let bias = verify_storage_proof(&storage_root, bias_slot, &req.bias_proof);

            SharedPointResult {
                gauge: req.gauge,
                epoch,
                bias,
                // Commit the protocol id and the EXACT account whose proof was just
                // verified above, so the on-chain whitelist authenticates the source.
                protocol_id: req.protocol_id,
                gauge_controller: req.gauge_controller,
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
            // Reject unknown protocol ids (fail-closed: panic => unprovable proof).
            let protocol = Protocol::try_from(req.protocol_id)
                .unwrap_or_else(|e| panic!("invalid protocol_id: {e}"));

            // Verify account proof to get storage root
            let storage_root =
                verify_account_proof(state_root, req.gauge_controller, &req.account_proof);

            // Derive the canonical slots in-circuit from (protocol, account, gauge).
            let slots = derive_account_slots(protocol, req.account, req.gauge);

            // Verify both storage proofs. Every protocol proves both slots, so both
            // proofs stay mandatory (fail-closed) even where a committed value is
            // derived from only one of the two words.
            let slope_word = verify_storage_proof(&storage_root, slots.slope, &req.slope_proof);
            let end_word = verify_storage_proof(&storage_root, slots.end, &req.end_proof);

            // Pendle packs its vote into one word and stores no expiry, so its two
            // words do not carry `(slope, end)` directly the way every other
            // protocol's do. See `decode_pendle_vote`.
            let (slope, end) = match protocol {
                Protocol::Pendle => decode_pendle_vote(end_word),
                _ => (slope_word, end_word),
            };

            // Verify last_vote. Fail-closed: every protocol except Pendle has a
            // last_vote slot, so its proof is mandatory. Accepting a missing proof
            // would let a prover under-report last_vote as zero without proving the
            // storage value. Only Pendle (no last_user_vote mapping) commits zero.
            let last_vote = match (&slots.last_vote, &req.last_vote_proof) {
                (Some(slot), Some(proof)) => verify_storage_proof(&storage_root, *slot, proof),
                (None, None) => U256::ZERO,
                (Some(_), None) => panic!("missing last_vote_proof for non-Pendle protocol"),
                (None, Some(_)) => panic!("unexpected last_vote_proof for Pendle protocol"),
            };

            SharedAccountResult {
                account: req.account,
                gauge: req.gauge,
                epoch,
                slope,
                end,
                last_vote,
                // Commit the protocol id and the EXACT account whose proof was just
                // verified above, so the on-chain whitelist authenticates the source.
                protocol_id: req.protocol_id,
                gauge_controller: req.gauge_controller,
            }
        })
        .collect()
}

/// Decode a Pendle account vote into the `(slope, end)` pair the on-chain
/// consumers expect, from the packed `VeBalance` word.
///
/// Pendle's VotingController stores `UserPoolData { uint64 weight; VeBalance {
/// uint128 bias; uint128 slope; } }`: `weight` alone in the user-vote slot and the
/// packed `VeBalance` in the next one, so the second word holds both fields
/// (`bias` low, `slope` high). Pendle stores no expiry: the vote decays linearly,
/// so the expiry is where that line reaches zero, `bias / slope`. These are the
/// same values `VerifierPendle._extractUserSlope` commits on the MPT path, and
/// floor division of the same two operands agrees with its uint128 arithmetic.
///
/// The guard is on `slope`, the denominator, which is where the reference and this
/// deliberately differ. `VerifierPendle` gates the division on `bias > 0`, the
/// numerator, which does not protect it: a `(slope == 0, bias > 0)` word passes
/// that guard and divides by zero. The reference merely reverts one call there,
/// whereas a panic here makes the entire batch unprovable, so that shape must
/// commit `end = 0` instead. Wherever the reference yields a value at all, this
/// yields the same one.
///
/// That divergence is unreachable rather than merely unlikely: Pendle derives the
/// two fields together as `bias = slope * expiry` (`convertToVeBalance`), so a zero
/// slope forces a zero bias, and no authentic vote can carry `(0, bias > 0)`. The
/// guard is there for a word that Pendle's own math cannot produce, and committing
/// zeros for it is the conservative reading anyway: the lens treats `slope == 0` as
/// no vote, so it can only ever under-credit, never over-credit.
fn decode_pendle_vote(packed: U256) -> (U256, U256) {
    let slope: U256 = packed >> 128;
    let bias = packed & U256::from(u128::MAX);
    let end = if slope.is_zero() {
        U256::ZERO
    } else {
        bias / slope
    };
    (slope, end)
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
    use alloy_sol_types::SolValue;
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
        let protocol = Protocol::Curve;
        // Store the value at the canonical derived slot; the guest recomputes it.
        let bias_slot = derive_point_slot(protocol, gauge, TEST_EPOCH);

        let (storage_root, bias_proof) = create_storage_trie_proof(bias_slot, bias_value);
        let (state_root, account_proof) = create_account_trie_proof(gauge_controller, storage_root);

        let request = PointRequest {
            protocol_id: protocol.as_u8(),
            gauge,
            gauge_controller,
            account_proof,
            bias_proof,
        };

        let results = process_point_requests(&state_root, TEST_EPOCH, &[request]);

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].gauge, gauge);
        assert_eq!(results[0].epoch, TEST_EPOCH);
        assert_eq!(results[0].bias, bias_value);
    }

    // Binding invariant (the v2.2 security hinge): the committed `gauge_controller`
    // and `protocol_id` are exactly the request's, and `gauge_controller` is the same
    // account whose account proof was verified (so the on-chain whitelist authenticates
    // the real source of the value). Covers both point and account results.
    #[test]
    fn test_committed_controller_is_proven_account() {
        let gauge = TEST_GAUGE.parse::<Address>().unwrap();
        let account = TEST_ACCOUNT.parse::<Address>().unwrap();
        // A specific, non-default controller: this is the account the proof is built
        // against, and must surface unchanged on the committed result.
        let gauge_controller = Address::repeat_byte(0xc7);
        let protocol = Protocol::Curve;

        // Point result
        let bias_slot = derive_point_slot(protocol, gauge, TEST_EPOCH);
        let (p_root, bias_proof) = create_storage_trie_proof(bias_slot, U256::from(1u64));
        let (p_state, p_account_proof) = create_account_trie_proof(gauge_controller, p_root);
        let p = &process_point_requests(
            &p_state,
            TEST_EPOCH,
            &[PointRequest {
                protocol_id: protocol.as_u8(),
                gauge,
                gauge_controller,
                account_proof: p_account_proof,
                bias_proof,
            }],
        )[0];
        assert_eq!(p.protocol_id, protocol.as_u8());
        assert_eq!(p.gauge_controller, gauge_controller);

        // Account result
        let slots = derive_account_slots(protocol, account, gauge);
        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = EthTrie::new(memdb.clone());
        for (slot, value) in [
            (slots.slope, U256::from(5u64)),
            (slots.end, U256::from(6u64)),
            (slots.last_vote.unwrap(), U256::from(7u64)),
        ] {
            let key = keccak256(&slot.to_be_bytes::<32>());
            let mut rlp_value = Vec::new();
            value.encode(&mut rlp_value);
            trie.insert(&key, &rlp_value).unwrap();
        }
        let a_root = B256::from(trie.root_hash().unwrap().0);
        let slope_proof = trie
            .get_proof(&keccak256(&slots.slope.to_be_bytes::<32>()))
            .unwrap();
        let end_proof = trie
            .get_proof(&keccak256(&slots.end.to_be_bytes::<32>()))
            .unwrap();
        let lv_proof = trie
            .get_proof(&keccak256(&slots.last_vote.unwrap().to_be_bytes::<32>()))
            .unwrap();
        let (a_state, a_account_proof) = create_account_trie_proof(gauge_controller, a_root);
        let a = &process_account_requests(
            &a_state,
            TEST_EPOCH,
            &[AccountRequest {
                protocol_id: protocol.as_u8(),
                account,
                gauge,
                gauge_controller,
                account_proof: a_account_proof,
                slope_proof,
                end_proof,
                last_vote_proof: Some(lv_proof),
            }],
        )[0];
        assert_eq!(a.protocol_id, protocol.as_u8());
        assert_eq!(a.gauge_controller, gauge_controller);
    }

    #[test]
    fn test_process_point_requests_preserves_epoch() {
        let gauge = TEST_GAUGE.parse::<Address>().unwrap();
        let gauge_controller = TEST_ACCOUNT.parse::<Address>().unwrap();
        let bias_value = U256::from(500u64);
        let custom_epoch = 1234567890u64;
        let protocol = Protocol::Balancer;
        let bias_slot = derive_point_slot(protocol, gauge, custom_epoch);

        let (storage_root, bias_proof) = create_storage_trie_proof(bias_slot, bias_value);
        let (state_root, account_proof) = create_account_trie_proof(gauge_controller, storage_root);

        let request = PointRequest {
            protocol_id: protocol.as_u8(),
            gauge,
            gauge_controller,
            account_proof,
            bias_proof,
        };

        let results = process_point_requests(&state_root, custom_epoch, &[request]);

        assert_eq!(results[0].epoch, custom_epoch);
        assert_eq!(results[0].bias, bias_value);
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

        let protocol = Protocol::Curve;
        let slots = derive_account_slots(protocol, account, gauge);
        let last_vote_slot = slots.last_vote.expect("curve has last_vote");

        // Create a trie with all three values at their canonical derived slots.
        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = EthTrie::new(memdb.clone());

        for (slot, value) in [
            (slots.slope, slope_value),
            (slots.end, end_value),
            (last_vote_slot, last_vote_value),
        ] {
            let key = keccak256(&slot.to_be_bytes::<32>());
            let mut rlp_value = Vec::new();
            value.encode(&mut rlp_value);
            trie.insert(&key, &rlp_value).unwrap();
        }

        let storage_root = B256::from(trie.root_hash().unwrap().0);
        let slope_proof = trie
            .get_proof(&keccak256(&slots.slope.to_be_bytes::<32>()))
            .unwrap();
        let end_proof = trie
            .get_proof(&keccak256(&slots.end.to_be_bytes::<32>()))
            .unwrap();
        let last_vote_proof = trie
            .get_proof(&keccak256(&last_vote_slot.to_be_bytes::<32>()))
            .unwrap();

        let (state_root, account_proof) = create_account_trie_proof(gauge_controller, storage_root);

        let request = AccountRequest {
            protocol_id: protocol.as_u8(),
            account,
            gauge,
            gauge_controller,
            account_proof,
            slope_proof,
            end_proof,
            last_vote_proof: Some(last_vote_proof),
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

        // Pendle has no last_user_vote mapping, so the guest derives None.
        let slots = derive_account_slots(Protocol::Pendle, account, gauge);
        assert!(slots.last_vote.is_none());

        let (state_root, request) = pendle_account_request(
            account,
            gauge,
            gauge_controller,
            PENDLE_SAMPLE_WEIGHT,
            pendle_packed(PENDLE_SAMPLE_BIAS, PENDLE_SAMPLE_SLOPE),
        );

        let results = process_account_requests(&state_root, TEST_EPOCH, &[request]);

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].slope, PENDLE_SAMPLE_SLOPE);
        assert_eq!(results[0].last_vote, U256::ZERO);
    }

    // =========================================================================
    // Pendle packed-VeBalance decoding
    // =========================================================================

    // Pinned from mainnet at block 17373523 (`getUserPoolVote` + `cast storage` on the
    // Pendle VotingController 0x44087E105137a5095c008AaB6a6530182821F2F0). The two
    // words of this account's vote are:
    //   S[finalSlot]   = 0x0000000000000000000000000000000000000000000000000928ca80cfc20000
    //   S[finalSlot+1] = 0x00000000000000000012e2b3e59ac3dc000000000007af859095ea8d0bdd3c00
    // i.e. weight alone, then the packed VeBalance (bias low 128, slope high 128).
    const PENDLE_SAMPLE_ACCOUNT: &str = "0xd8fa8dc5adec503acc5e026a98f32ca5c1fa289a";
    const PENDLE_SAMPLE_GAUGE: &str = "0x7d49e5adc0eaad9c027857767638613253ef125f";
    const PENDLE_SAMPLE_WEIGHT: U256 = U256::from_limbs([660000000000000000, 0, 0, 0]);
    const PENDLE_SAMPLE_SLOPE: U256 = U256::from_limbs([5315811859940316, 0, 0, 0]);
    // 9291358707257600007552000 = 0x07af859095ea8d0bdd3c00, wider than one u64 limb.
    const PENDLE_SAMPLE_BIAS: U256 = U256::from_limbs([10418491204501847040, 503685, 0, 0]);
    // bias / slope, the expiry the on-chain consumers read as `end`.
    const PENDLE_SAMPLE_END: U256 = U256::from_limbs([1747872000, 0, 0, 0]);

    /// Pack a `VeBalance { uint128 bias; uint128 slope; }` the way Solidity lays it
    /// out in one word: first-declared field in the low bits.
    fn pendle_packed(bias: U256, slope: U256) -> U256 {
        (slope << 128) | bias
    }

    /// Build a Pendle account request whose two vote words sit at their canonical
    /// derived slots, mirroring the on-chain layout: `weight` at the user-vote slot,
    /// the packed `VeBalance` at the next one.
    fn pendle_account_request(
        account: Address,
        gauge: Address,
        gauge_controller: Address,
        weight: U256,
        packed: U256,
    ) -> (B256, AccountRequest) {
        let slots = derive_account_slots(Protocol::Pendle, account, gauge);
        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = EthTrie::new(memdb.clone());

        for (slot, value) in [(slots.slope, weight), (slots.end, packed)] {
            let key = keccak256(&slot.to_be_bytes::<32>());
            let mut rlp_value = Vec::new();
            value.encode(&mut rlp_value);
            trie.insert(&key, &rlp_value).unwrap();
        }

        let storage_root = B256::from(trie.root_hash().unwrap().0);
        let slope_proof = trie
            .get_proof(&keccak256(&slots.slope.to_be_bytes::<32>()))
            .unwrap();
        let end_proof = trie
            .get_proof(&keccak256(&slots.end.to_be_bytes::<32>()))
            .unwrap();
        let (state_root, account_proof) = create_account_trie_proof(gauge_controller, storage_root);

        (
            state_root,
            AccountRequest {
                protocol_id: Protocol::Pendle.as_u8(),
                account,
                gauge,
                gauge_controller,
                account_proof,
                slope_proof,
                end_proof,
                last_vote_proof: None,
            },
        )
    }

    /// Mirror of `PendleOracleLens.getAccountVotes` (contracts-monorepo), so the
    /// guest's committed values can be checked against what the consumer computes
    /// from them. The `lastUpdate == 0` revert is oracle state, not vote data, and
    /// has no counterpart here.
    fn lens_account_votes(slope: U256, end: U256, epoch: u64) -> U256 {
        let epoch = U256::from(epoch);
        if epoch >= end {
            return U256::ZERO;
        }
        slope * (end - epoch)
    }

    /// Mirror of `PendleOracleLens.isVoteValid` (contracts-monorepo).
    fn lens_is_vote_valid(slope: U256, end: U256, epoch: u64) -> bool {
        !(slope.is_zero() || U256::from(epoch) >= end)
    }

    // The core of the fix, against the pinned real mainnet vote: the guest must commit
    // the VeBalance's own slope and the derived expiry, both decoded out of the
    // single packed word, never the two raw words.
    #[test]
    fn test_pendle_decodes_packed_vebalance_from_mainnet_sample() {
        let account = PENDLE_SAMPLE_ACCOUNT.parse::<Address>().unwrap();
        let gauge = PENDLE_SAMPLE_GAUGE.parse::<Address>().unwrap();
        let gauge_controller = Protocol::Pendle.gauge_controller().unwrap();
        let packed = pendle_packed(PENDLE_SAMPLE_BIAS, PENDLE_SAMPLE_SLOPE);

        // Guard the fixture itself against a typo: these are the bytes read off chain.
        assert_eq!(
            packed,
            U256::from_str_radix(
                "00000000000000000012e2b3e59ac3dc000000000007af859095ea8d0bdd3c00",
                16
            )
            .unwrap(),
            "packed fixture must equal the word read at S[finalSlot+1]"
        );
        assert_eq!(PENDLE_SAMPLE_BIAS / PENDLE_SAMPLE_SLOPE, PENDLE_SAMPLE_END);

        let (state_root, request) = pendle_account_request(
            account,
            gauge,
            gauge_controller,
            PENDLE_SAMPLE_WEIGHT,
            packed,
        );
        let results = process_account_requests(&state_root, TEST_EPOCH, &[request]);

        assert_eq!(results[0].slope, PENDLE_SAMPLE_SLOPE);
        assert_eq!(results[0].end, PENDLE_SAMPLE_END);
        assert_eq!(results[0].last_vote, U256::ZERO);
    }

    // Regression pinning the pre-fix behavior as gone: `slope` was the uint64 weight
    // from S[finalSlot] and `end` the whole packed word (~1.8e54), which made every
    // Pendle vote look unexpired and wildly overweighted to PendleOracleLens.
    #[test]
    fn test_pendle_no_longer_commits_raw_words() {
        let account = PENDLE_SAMPLE_ACCOUNT.parse::<Address>().unwrap();
        let gauge = PENDLE_SAMPLE_GAUGE.parse::<Address>().unwrap();
        let gauge_controller = Protocol::Pendle.gauge_controller().unwrap();
        let packed = pendle_packed(PENDLE_SAMPLE_BIAS, PENDLE_SAMPLE_SLOPE);

        let (state_root, request) = pendle_account_request(
            account,
            gauge,
            gauge_controller,
            PENDLE_SAMPLE_WEIGHT,
            packed,
        );
        let results = process_account_requests(&state_root, TEST_EPOCH, &[request]);

        assert_ne!(
            results[0].slope, PENDLE_SAMPLE_WEIGHT,
            "slope must not be the raw weight word"
        );
        assert_ne!(
            results[0].end, packed,
            "end must not be the raw packed word"
        );
        // The old `end` was the ~1.8e54 packed word, which no plausible epoch ever
        // reaches, so the vote read as live forever. The fixed `end` is a real unix
        // timestamp: still live at TEST_EPOCH, spent once the epoch reaches it.
        assert!(results[0].end < U256::from(u64::MAX));
        assert!(lens_is_vote_valid(
            results[0].slope,
            results[0].end,
            TEST_EPOCH
        ));
        assert!(!lens_is_vote_valid(
            results[0].slope,
            results[0].end,
            PENDLE_SAMPLE_END.to::<u64>()
        ));
    }

    // (a) A zero vote decodes to zeros, and reads as no votes / invalid on the lens,
    // matching what VerifierPendle commits for the same storage.
    #[test]
    fn test_pendle_zero_vote_decodes_to_zero() {
        let account = TEST_ACCOUNT.parse::<Address>().unwrap();
        let gauge = TEST_GAUGE.parse::<Address>().unwrap();
        let gauge_controller = Protocol::Pendle.gauge_controller().unwrap();

        let (state_root, request) =
            pendle_account_request(account, gauge, gauge_controller, U256::ZERO, U256::ZERO);
        let results = process_account_requests(&state_root, TEST_EPOCH, &[request]);

        assert_eq!(results[0].slope, U256::ZERO);
        assert_eq!(results[0].end, U256::ZERO);
        assert_eq!(
            lens_account_votes(results[0].slope, results[0].end, TEST_EPOCH),
            U256::ZERO
        );
        assert!(!lens_is_vote_valid(
            results[0].slope,
            results[0].end,
            TEST_EPOCH
        ));
    }

    // (b) A zero-slope word with a non-zero bias is the div-by-zero shape. Guarding
    // the numerator (as VerifierPendle does) would panic here and brick the whole
    // batch, so this rides alongside a healthy request to pin that it does not.
    #[test]
    fn test_pendle_zero_slope_in_batch_commits_zero_end_without_panic() {
        let gauge = TEST_GAUGE.parse::<Address>().unwrap();
        let gauge_controller = Protocol::Pendle.gauge_controller().unwrap();
        let healthy = PENDLE_SAMPLE_ACCOUNT.parse::<Address>().unwrap();
        let degenerate = Address::repeat_byte(0x5a);

        // Both accounts must live under one storage root for a single batch.
        let healthy_slots = derive_account_slots(Protocol::Pendle, healthy, gauge);
        let degenerate_slots = derive_account_slots(Protocol::Pendle, degenerate, gauge);
        let healthy_packed = pendle_packed(PENDLE_SAMPLE_BIAS, PENDLE_SAMPLE_SLOPE);
        // slope == 0 (high 128 empty), bias > 0: the denominator is the zero one.
        let degenerate_packed = pendle_packed(U256::from(12345u64), U256::ZERO);
        assert!(!degenerate_packed.is_zero());

        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = EthTrie::new(memdb.clone());
        for (slot, value) in [
            (healthy_slots.slope, PENDLE_SAMPLE_WEIGHT),
            (healthy_slots.end, healthy_packed),
            (degenerate_slots.slope, U256::from(7u64)),
            (degenerate_slots.end, degenerate_packed),
        ] {
            let key = keccak256(&slot.to_be_bytes::<32>());
            let mut rlp_value = Vec::new();
            value.encode(&mut rlp_value);
            trie.insert(&key, &rlp_value).unwrap();
        }
        let storage_root = B256::from(trie.root_hash().unwrap().0);
        let (state_root, account_proof) = create_account_trie_proof(gauge_controller, storage_root);

        let mut build = |account: Address, slots: shared::protocol::AccountSlots| AccountRequest {
            protocol_id: Protocol::Pendle.as_u8(),
            account,
            gauge,
            gauge_controller,
            account_proof: account_proof.clone(),
            slope_proof: trie
                .get_proof(&keccak256(&slots.slope.to_be_bytes::<32>()))
                .unwrap(),
            end_proof: trie
                .get_proof(&keccak256(&slots.end.to_be_bytes::<32>()))
                .unwrap(),
            last_vote_proof: None,
        };

        let results = process_account_requests(
            &state_root,
            TEST_EPOCH,
            &[
                build(degenerate, degenerate_slots),
                build(healthy, healthy_slots),
            ],
        );

        // The degenerate vote is neutralized, not fatal...
        assert_eq!(results[0].slope, U256::ZERO);
        assert_eq!(results[0].end, U256::ZERO);
        assert!(!lens_is_vote_valid(
            results[0].slope,
            results[0].end,
            TEST_EPOCH
        ));
        // ...and its neighbour in the same batch still decodes correctly.
        assert_eq!(results[1].slope, PENDLE_SAMPLE_SLOPE);
        assert_eq!(results[1].end, PENDLE_SAMPLE_END);
    }

    // (c) At the decay boundary the lens must read the vote as spent, from the
    // values the guest committed.
    #[test]
    fn test_pendle_epoch_equal_to_end_reads_as_expired() {
        let account = TEST_ACCOUNT.parse::<Address>().unwrap();
        let gauge = TEST_GAUGE.parse::<Address>().unwrap();
        let gauge_controller = Protocol::Pendle.gauge_controller().unwrap();

        // Pick bias = slope * TEST_EPOCH so the decoded end lands exactly on TEST_EPOCH.
        let slope = U256::from(1_000_000u64);
        let bias = slope * U256::from(TEST_EPOCH);
        let (state_root, request) = pendle_account_request(
            account,
            gauge,
            gauge_controller,
            PENDLE_SAMPLE_WEIGHT,
            pendle_packed(bias, slope),
        );
        let results = process_account_requests(&state_root, TEST_EPOCH, &[request]);

        assert_eq!(results[0].end, U256::from(TEST_EPOCH));
        assert_eq!(
            lens_account_votes(results[0].slope, results[0].end, TEST_EPOCH),
            U256::ZERO
        );
        assert!(!lens_is_vote_valid(
            results[0].slope,
            results[0].end,
            TEST_EPOCH
        ));
        // One epoch earlier the same vote is still live, so `end` is a real boundary
        // and not a value that reads as expired for every epoch.
        assert!(lens_is_vote_valid(
            results[0].slope,
            results[0].end,
            TEST_EPOCH - 1
        ));
    }

    #[test]
    fn test_process_account_requests_preserves_fields() {
        let account = TEST_ACCOUNT.parse::<Address>().unwrap();
        let gauge = TEST_GAUGE.parse::<Address>().unwrap();
        let gauge_controller = Address::repeat_byte(0x33);
        let custom_epoch = 9876543210u64;

        let slope_value = U256::from(50u64);
        let end_value = U256::from(1500000000u64);
        let last_vote_value = U256::from(1700000000u64);
        let protocol = Protocol::Balancer;
        let slots = derive_account_slots(protocol, account, gauge);

        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = EthTrie::new(memdb.clone());

        // Balancer has a last_vote slot, so its proof is mandatory (fail-closed).
        for (slot, value) in [
            (slots.slope, slope_value),
            (slots.end, end_value),
            (slots.last_vote.unwrap(), last_vote_value),
        ] {
            let key = keccak256(&slot.to_be_bytes::<32>());
            let mut rlp_value = Vec::new();
            value.encode(&mut rlp_value);
            trie.insert(&key, &rlp_value).unwrap();
        }

        let storage_root = B256::from(trie.root_hash().unwrap().0);
        let slope_proof = trie
            .get_proof(&keccak256(&slots.slope.to_be_bytes::<32>()))
            .unwrap();
        let end_proof = trie
            .get_proof(&keccak256(&slots.end.to_be_bytes::<32>()))
            .unwrap();
        let last_vote_proof = trie
            .get_proof(&keccak256(&slots.last_vote.unwrap().to_be_bytes::<32>()))
            .unwrap();

        let (state_root, account_proof) = create_account_trie_proof(gauge_controller, storage_root);

        let request = AccountRequest {
            protocol_id: protocol.as_u8(),
            account,
            gauge,
            gauge_controller,
            account_proof,
            slope_proof,
            end_proof,
            last_vote_proof: Some(last_vote_proof),
        };

        let results = process_account_requests(&state_root, custom_epoch, &[request]);

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].account, account);
        assert_eq!(results[0].gauge, gauge);
        assert_eq!(results[0].epoch, custom_epoch);
    }

    // =========================================================================
    // in-circuit slot-derivation security tests
    // =========================================================================

    /// Build a point request whose bias value lives at `stored_slot`, but is
    /// submitted with `protocol`/`gauge`. Used to test label binding.
    fn point_request_at_slot(
        protocol: Protocol,
        gauge: Address,
        gauge_controller: Address,
        stored_slot: U256,
        bias_value: U256,
    ) -> (B256, PointRequest) {
        let (storage_root, bias_proof) = create_storage_trie_proof(stored_slot, bias_value);
        let (state_root, account_proof) = create_account_trie_proof(gauge_controller, storage_root);
        (
            state_root,
            PointRequest {
                protocol_id: protocol.as_u8(),
                gauge,
                gauge_controller,
                account_proof,
                bias_proof,
            },
        )
    }

    // Label binding (cases a/e/b): a storage proof valid for one (label) cannot be
    // relabeled to forge a value under another. The guest derives the slot from the
    // submitted label, so the proof (covering the original slot) becomes a valid
    // *exclusion* proof for the derived slot => the forged value never surfaces
    // (it reads as 0). This is the core slot-binding property.

    // (a) bias proof for gauge A relabeled as gauge B: yields 0, not the planted value.
    #[test]
    fn test_adversarial_bias_gauge_relabel_yields_zero_not_forged() {
        let gauge_a = TEST_GAUGE.parse::<Address>().unwrap();
        let gauge_b = Address::repeat_byte(0xbb);
        let gc = TEST_ACCOUNT.parse::<Address>().unwrap();
        let slot_a = derive_point_slot(Protocol::Curve, gauge_a, TEST_EPOCH);
        let (state_root, req) =
            point_request_at_slot(Protocol::Curve, gauge_b, gc, slot_a, U256::from(999u64));
        let results = process_point_requests(&state_root, TEST_EPOCH, &[req]);
        assert_ne!(
            results[0].bias,
            U256::from(999u64),
            "relabel must not forge"
        );
        assert_eq!(results[0].bias, U256::ZERO);
    }

    // (e) value at Curve's slot submitted under Balancer: different formula => 0.
    #[test]
    fn test_adversarial_cross_protocol_relabel_yields_zero() {
        let gauge = TEST_GAUGE.parse::<Address>().unwrap();
        let gc = TEST_ACCOUNT.parse::<Address>().unwrap();
        let curve_slot = derive_point_slot(Protocol::Curve, gauge, TEST_EPOCH);
        // Sanity: the two protocols derive different slots for the same gauge/epoch.
        assert_ne!(
            curve_slot,
            derive_point_slot(Protocol::Balancer, gauge, TEST_EPOCH)
        );
        let (state_root, req) =
            point_request_at_slot(Protocol::Balancer, gauge, gc, curve_slot, U256::from(7u64));
        let results = process_point_requests(&state_root, TEST_EPOCH, &[req]);
        assert_eq!(results[0].bias, U256::ZERO);
    }

    // (b) account slope/end proof for account X relabeled as account Y: yields 0.
    #[test]
    fn test_adversarial_account_relabel_yields_zero() {
        let account_x = TEST_ACCOUNT.parse::<Address>().unwrap();
        let account_y = Address::repeat_byte(0x77);
        let gauge = TEST_GAUGE.parse::<Address>().unwrap();
        let gc = Address::repeat_byte(0x11);

        // Store slope/end at account X's canonical slots.
        let slots_x = derive_account_slots(Protocol::Curve, account_x, gauge);
        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = EthTrie::new(memdb.clone());
        for (slot, value) in [
            (slots_x.slope, U256::from(5u64)),
            (slots_x.end, U256::from(6u64)),
        ] {
            let key = keccak256(&slot.to_be_bytes::<32>());
            let mut rlp_value = Vec::new();
            value.encode(&mut rlp_value);
            trie.insert(&key, &rlp_value).unwrap();
        }
        let storage_root = B256::from(trie.root_hash().unwrap().0);
        let slope_proof = trie
            .get_proof(&keccak256(&slots_x.slope.to_be_bytes::<32>()))
            .unwrap();
        let end_proof = trie
            .get_proof(&keccak256(&slots_x.end.to_be_bytes::<32>()))
            .unwrap();
        // Curve has a last_vote slot, so its proof is mandatory (fail-closed). Supply
        // an exclusion proof so the test exercises the relabel binding, not the bypass.
        let last_vote_proof = trie
            .get_proof(&keccak256(&slots_x.last_vote.unwrap().to_be_bytes::<32>()))
            .unwrap();
        let (state_root, account_proof) = create_account_trie_proof(gc, storage_root);

        // Submit labeled as account Y => guest derives Y's slots => exclusion => 0.
        let req = AccountRequest {
            protocol_id: Protocol::Curve.as_u8(),
            account: account_y,
            gauge,
            gauge_controller: gc,
            account_proof,
            slope_proof,
            end_proof,
            last_vote_proof: Some(last_vote_proof),
        };
        let results = process_account_requests(&state_root, TEST_EPOCH, &[req]);
        assert_eq!(results[0].slope, U256::ZERO);
        assert_eq!(results[0].end, U256::ZERO);
        assert_eq!(results[0].last_vote, U256::ZERO);
    }

    // Fail-closed: omitting the last_vote proof for a non-Pendle protocol must panic
    // rather than silently committing last_vote = 0 (soundness gap).
    #[test]
    #[should_panic(expected = "missing last_vote_proof for non-Pendle protocol")]
    fn test_missing_last_vote_proof_non_pendle_panics() {
        let account = TEST_ACCOUNT.parse::<Address>().unwrap();
        let gauge = TEST_GAUGE.parse::<Address>().unwrap();
        let gc = Address::repeat_byte(0x11);
        let slots = derive_account_slots(Protocol::Curve, account, gauge);
        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = EthTrie::new(memdb.clone());
        for (slot, value) in [
            (slots.slope, U256::from(5u64)),
            (slots.end, U256::from(6u64)),
        ] {
            let key = keccak256(&slot.to_be_bytes::<32>());
            let mut rlp_value = Vec::new();
            value.encode(&mut rlp_value);
            trie.insert(&key, &rlp_value).unwrap();
        }
        let storage_root = B256::from(trie.root_hash().unwrap().0);
        let slope_proof = trie
            .get_proof(&keccak256(&slots.slope.to_be_bytes::<32>()))
            .unwrap();
        let end_proof = trie
            .get_proof(&keccak256(&slots.end.to_be_bytes::<32>()))
            .unwrap();
        let (state_root, account_proof) = create_account_trie_proof(gc, storage_root);
        let req = AccountRequest {
            protocol_id: Protocol::Curve.as_u8(),
            account,
            gauge,
            gauge_controller: gc,
            account_proof,
            slope_proof,
            end_proof,
            last_vote_proof: None, // Curve requires it => must panic
        };
        let _ = process_account_requests(&state_root, TEST_EPOCH, &[req]);
    }

    // Unknown protocol_id is rejected (fail-closed panic).
    #[test]
    #[should_panic(expected = "invalid protocol_id")]
    fn test_unknown_protocol_id_panics() {
        let gauge = TEST_GAUGE.parse::<Address>().unwrap();
        let gc = TEST_ACCOUNT.parse::<Address>().unwrap();
        let (storage_root, bias_proof) =
            create_storage_trie_proof(U256::from(1u64), U256::from(1u64));
        let (state_root, account_proof) = create_account_trie_proof(gc, storage_root);
        let req = PointRequest {
            protocol_id: 99, // not a known protocol
            gauge,
            gauge_controller: gc,
            account_proof,
            bias_proof,
        };
        let _ = process_point_requests(&state_root, TEST_EPOCH, &[req]);
    }

    // PublicValues ABI layout (v2.2 schema). PointResult and AccountResult now carry
    // `protocolId` (uint8) + `gaugeController` (address) appended after the prior fields.
    // The golden byte fixture pins the on-wire layout, so a field reorder/add/retype in
    // the sol! block changes these bytes and fails here. This schema must match the
    // ZKVerifier.sol structs + _decodePublicValues in contracts-monorepo.
    #[test]
    fn test_public_values_abi_schema() {
        const GOLDEN_PUBLIC_VALUES_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000020abababababababababababababababababababababababababababababababab00000000000000000000000000000000000000000000000000000000672c030000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000000100000000000000000000000026f7786de3e6d9bd37fcf47be6f2bc455a21b74a00000000000000000000000000000000000000000000000000000000672c0300000000000000000000000000000000000000000000000000000000000000007b0000000000000000000000000000000000000000000000000000000000000004000000000000000000000000fac2f11ba2577d5122dc1ec5301d35b16688251e0000000000000000000000000000000000000000000000000000000000000001000000000000000000000000fac2f11ba2577d5122dc1ec5301d35b16688251e00000000000000000000000026f7786de3e6d9bd37fcf47be6f2bc455a21b74a00000000000000000000000000000000000000000000000000000000672c0300000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000000000000000000000000000000026f7786de3e6d9bd37fcf47be6f2bc455a21b74a";
        let pv = PublicValues {
            stateRoot: B256::repeat_byte(0xab),
            epoch: U256::from(TEST_EPOCH),
            pointResults: vec![PointResult {
                gauge: TEST_GAUGE.parse().unwrap(),
                epoch: U256::from(TEST_EPOCH),
                bias: U256::from(123u64),
                protocolId: 4,
                gaugeController: TEST_ACCOUNT.parse().unwrap(),
            }],
            accountResults: vec![AccountResult {
                account: TEST_ACCOUNT.parse().unwrap(),
                gauge: TEST_GAUGE.parse().unwrap(),
                epoch: U256::from(TEST_EPOCH),
                slope: U256::from(1u64),
                end: U256::from(2u64),
                lastVote: U256::from(3u64),
                protocolId: 0,
                gaugeController: TEST_GAUGE.parse().unwrap(),
            }],
        };
        let encoded = PublicValues::abi_encode(&pv);
        let golden = alloy_primitives::hex::decode(GOLDEN_PUBLIC_VALUES_HEX).unwrap();
        assert_eq!(encoded, golden, "PublicValues ABI layout changed");

        let decoded = PublicValues::abi_decode(&encoded, true).unwrap();
        assert_eq!(decoded.stateRoot, pv.stateRoot);
        assert_eq!(decoded.pointResults[0].bias, U256::from(123u64));
        assert_eq!(decoded.pointResults[0].protocolId, 4);
        assert_eq!(
            decoded.accountResults[0].gaugeController,
            pv.accountResults[0].gaugeController
        );
    }
}
