use sp1_sdk::{ProverClient, SP1Stdin};
use shared::{Input, Output, StorageProofRequest};
use alloy_primitives::{address, Address, B256, U256};
use alloy_rlp::{Encodable, RlpEncodable};
use eth_trie::{EthTrie, MemoryDB, Trie};
use sha3::{Digest, Keccak256};
use std::{
    env,
    path::{Path, PathBuf},
    sync::Arc,
};

const DEFAULT_ELF_REL_PATHS: [&str; 3] = [
    "../program/elf/riscv32im-succinct-zkvm-elf",
    "../target/elf-compilation/riscv32im-succinct-zkvm-elf/release/program",
    "../target/elf-compilation/riscv32im-succinct-zkvm-elf/debug/program",
];

fn load_elf() -> Vec<u8> {
    let mut candidates: Vec<String> = Vec::new();
    if let Ok(custom_path) = env::var("SP1_ELF_PATH") {
        candidates.push(custom_path);
    }
    candidates.extend(DEFAULT_ELF_REL_PATHS.iter().map(|path| path.to_string()));

    let mut errors = Vec::new();
    for candidate in candidates {
        let path = resolve_elf_path(&candidate);
        match std::fs::read(&path) {
            Ok(bytes) => return bytes,
            Err(err) => errors.push(format!("{}: {}", path.display(), err)),
        }
    }

    panic!(
        "Failed to read SP1 ELF. Tried:\n{}",
        errors.join("\n")
    );
}

fn resolve_elf_path(path: &str) -> PathBuf {
    let path = PathBuf::from(path);
    if path.is_absolute() {
        path
    } else {
        Path::new(env!("CARGO_MANIFEST_DIR")).join(path)
    }
}

#[derive(RlpEncodable)]
struct Account {
    nonce: U256,
    balance: U256,
    storage_root: B256,
    code_hash: B256,
}

fn build_mock_input() -> Input {
    let account = address!("0000000000000000000000000000000000000000");
    let slot = U256::ZERO;
    let value = U256::from(42);

    let (state_root, account_proof, storage_proof) =
        build_mock_proofs(account, slot, value);

    Input {
        state_root,
        proofs: vec![StorageProofRequest {
            account,
            slot,
            account_proof,
            storage_proof,
        }],
    }
}

fn build_mock_proofs(
    account: Address,
    slot: U256,
    value: U256,
) -> (B256, Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let storage_db = Arc::new(MemoryDB::new(true));
    let mut storage_trie = EthTrie::new(storage_db);
    let slot_key = keccak256(&slot.to_be_bytes::<32>());
    let storage_value = rlp_encode(&value);
    storage_trie
        .insert(&slot_key, &storage_value)
        .expect("Storage trie insert failed");
    let storage_root = storage_trie
        .root_hash()
        .expect("Storage trie root hash failed");
    let storage_proof = storage_trie
        .get_proof(&slot_key)
        .expect("Storage trie proof failed");

    let account_db = Arc::new(MemoryDB::new(true));
    let mut account_trie = EthTrie::new(account_db);
    let account_key = keccak256(account.as_slice());
    let account_value = rlp_encode(&Account {
        nonce: U256::ZERO,
        balance: U256::ZERO,
        storage_root: B256::from_slice(storage_root.as_bytes()),
        code_hash: B256::from_slice(&keccak256(&[])),
    });
    account_trie
        .insert(&account_key, &account_value)
        .expect("Account trie insert failed");
    let state_root = account_trie
        .root_hash()
        .expect("Account trie root hash failed");
    let account_proof = account_trie
        .get_proof(&account_key)
        .expect("Account trie proof failed");

    (
        B256::from_slice(state_root.as_bytes()),
        account_proof,
        storage_proof,
    )
}

fn rlp_encode<T: Encodable>(value: &T) -> Vec<u8> {
    let mut out = Vec::new();
    value.encode(&mut out);
    out
}

fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    hasher.finalize().into()
}

#[tokio::main]
async fn main() {
    sp1_sdk::utils::setup_logger();

    let client = ProverClient::new();
    let mut stdin = SP1Stdin::new();
    let elf = load_elf();

    // Mock Data - In production, fetch this via RPC (eth_getProof)
    let input = build_mock_input();

    stdin.write(&input);

    println!("Executing in mock mode...");
    let (mut public_values, report) = client
        .execute(elf.as_slice(), stdin)
        .run()
        .expect("Execution failed");
    println!("Execution successful!");

    let output = public_values.read::<Output>();
    println!("Cycles: {}", report.total_instruction_count());
    println!("Output State Root: {:?}", output.state_root);
    println!("Verified {} slots", output.results.len());
}
