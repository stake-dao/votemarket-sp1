//! Keccak hashing and ABI word-encoding helpers used by storage-slot derivation.

use alloy_primitives::{Address, U256};
use sha3::{Digest, Keccak256};

/// Keccak256 of an arbitrary byte slice.
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Keccak256 of the concatenation of 32-byte words (Solidity `abi.encodePacked`
/// of `bytes32` words, then hashed).
pub fn keccak_abi_encode(words: &[[u8; 32]]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(words.len() * 32);
    for word in words {
        buf.extend_from_slice(word);
    }
    keccak256(&buf)
}

/// Encode a `U256` as a 32-byte big-endian word.
pub fn encode_u256(value: U256) -> [u8; 32] {
    value.to_be_bytes::<32>()
}

/// Encode a `u128` left-padded into a 32-byte word.
pub fn encode_uint128(value: u128) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[16..].copy_from_slice(&value.to_be_bytes());
    out
}

/// Encode an `Address` left-padded into a 32-byte word.
pub fn encode_address(address: Address) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[12..].copy_from_slice(address.as_slice());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{address, hex};

    const TEST_EPOCH: u64 = 1730937600;
    const KECCAK_EMPTY: &str = "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470";
    const KECCAK_HELLO: &str = "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8";

    #[test]
    fn test_keccak256_empty_input() {
        assert_eq!(hex::encode(keccak256(&[])), KECCAK_EMPTY);
    }

    #[test]
    fn test_keccak256_hello() {
        assert_eq!(hex::encode(keccak256(b"hello")), KECCAK_HELLO);
    }

    #[test]
    fn test_keccak256_deterministic() {
        assert_eq!(keccak256(b"test input"), keccak256(b"test input"));
    }

    #[test]
    fn test_keccak256_different_inputs_different_outputs() {
        assert_ne!(keccak256(b"input1"), keccak256(b"input2"));
    }

    #[test]
    fn test_keccak_abi_encode_single_word() {
        let word = [0x12_u8; 32];
        assert_eq!(keccak_abi_encode(&[word]), keccak256(&word));
    }

    #[test]
    fn test_keccak_abi_encode_two_words() {
        let word1 = [0x11_u8; 32];
        let word2 = [0x22_u8; 32];
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(&word1);
        buf[32..].copy_from_slice(&word2);
        assert_eq!(keccak_abi_encode(&[word1, word2]), keccak256(&buf));
    }

    #[test]
    fn test_keccak_abi_encode_empty() {
        assert_eq!(keccak_abi_encode(&[]), keccak256(&[]));
    }

    #[test]
    fn test_encode_u256_zero() {
        assert_eq!(encode_u256(U256::ZERO), [0u8; 32]);
    }

    #[test]
    fn test_encode_u256_one() {
        let mut expected = [0u8; 32];
        expected[31] = 1;
        assert_eq!(encode_u256(U256::from(1)), expected);
    }

    #[test]
    fn test_encode_u256_max() {
        assert_eq!(encode_u256(U256::MAX), [0xff_u8; 32]);
    }

    #[test]
    fn test_encode_address_zero() {
        assert_eq!(encode_address(Address::ZERO), [0u8; 32]);
    }

    #[test]
    fn test_encode_address_preserves_bytes() {
        let addr = address!("26f7786de3e6d9bd37fcf47be6f2bc455a21b74a");
        let result = encode_address(addr);
        assert_eq!(result[..12], [0u8; 12]);
        assert_eq!(&result[12..], addr.as_slice());
    }

    #[test]
    fn test_encode_uint128_epoch() {
        let result = encode_uint128(TEST_EPOCH as u128);
        assert_eq!(result[..16], [0u8; 16]);
        assert_eq!(result[28..], [0x67, 0x2C, 0x03, 0x00]);
    }

    #[test]
    fn test_encode_uint128_max() {
        let result = encode_uint128(u128::MAX);
        assert_eq!(result[..16], [0u8; 16]);
        assert_eq!(result[16..], [0xff_u8; 16]);
    }
}
