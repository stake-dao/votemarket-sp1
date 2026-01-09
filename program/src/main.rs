#![no_main]
sp1_zkvm::entrypoint!(main);

use shared::{Input, Output, StorageResult};
use alloy_primitives::{Address, B256, U256};
use alloy_rlp::{Decodable, RlpDecodable};
use eth_trie::{EthTrie, MemoryDB, Trie};
use ethereum_types::H256;
use sha3::{Digest, Keccak256};
use std::sync::Arc;

#[derive(RlpDecodable)]
struct Account {
    nonce: U256,
    balance: U256,
    storage_root: B256,
    code_hash: B256,
}

pub fn main() {
    let input = sp1_zkvm::io::read::<Input>();

    let mut results = Vec::new();

    for proof in input.proofs {
        // 1. Verify Account Proof to get Storage Root
        let storage_root = verify_account_proof(&input.state_root, proof.account, &proof.account_proof);

        // 2. Verify Storage Proof to get Value
        let value = verify_storage_proof(&storage_root, proof.slot, &proof.storage_proof);

        results.push(StorageResult {
            account: proof.account,
            slot: proof.slot,
            value,
        });
    }

    let output = Output {
        state_root: input.state_root,
        results,
    };

    sp1_zkvm::io::commit(&output);
}

fn verify_account_proof(state_root: &B256, address: Address, proof: &[Vec<u8>]) -> B256 {
    let root = H256::from(state_root.0);
    let key = keccak256(address.as_slice());
    let trie = EthTrie::new(Arc::new(MemoryDB::new(true)));
    let value = trie
        .verify_proof(root, &key, proof.to_vec())
        .expect("Invalid state root or proof")
        .expect("Account not found");

    let mut slice = value.as_slice();
    let account = Account::decode(&mut slice).unwrap();
    account.storage_root
}

fn verify_storage_proof(storage_root: &B256, slot: U256, proof: &[Vec<u8>]) -> U256 {
    let root = H256::from(storage_root.0);
    let key = keccak256(&slot.to_be_bytes::<32>());
    let trie = EthTrie::new(Arc::new(MemoryDB::new(true)));
    let value = trie
        .verify_proof(root, &key, proof.to_vec())
        .expect("Invalid storage root or proof");

    match value {
        Some(value) => {
            let mut slice = value.as_slice();
            U256::decode(&mut slice).unwrap()
        }
        None => U256::ZERO,
    }
}


fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    hasher.finalize().into()
}
