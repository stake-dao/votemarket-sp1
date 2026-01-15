//! Proof persistence and artifact generation.

use alloy_primitives::hex;
use shared::Output;
use std::{env, fs, path::Path, path::PathBuf};

use crate::config::ProofKind;
use crate::types::ProofArtifact;

/// Save proof binary and JSON artifact to disk.
pub fn persist_proof(
    program_vkey: String,
    proof_kind: ProofKind,
    proof: &sp1_sdk::SP1ProofWithPublicValues,
    output: Output,
) -> Result<(), String> {
    let output_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("output");
    fs::create_dir_all(&output_dir).map_err(|err| format!("failed to create output dir: {err}"))?;

    let proof_path = env::var("PROOF_OUTPUT").unwrap_or_else(|_| "proof.bin".to_string());
    let proof_path = PathBuf::from(proof_path);
    let proof_path = if proof_path.is_relative() {
        output_dir.join(proof_path)
    } else {
        proof_path
    };

    proof
        .save(&proof_path)
        .map_err(|err| format!("failed to save proof: {err}"))?;

    let proof_json_path = env::var("PROOF_JSON").unwrap_or_else(|_| "proof.json".to_string());
    let proof_json_path = PathBuf::from(proof_json_path);
    let proof_json_path = if proof_json_path.is_relative() {
        output_dir.join(proof_json_path)
    } else {
        proof_json_path
    };

    let proof_bytes = match proof_kind {
        ProofKind::Plonk | ProofKind::Groth16 => Some(format!("0x{}", hex::encode(proof.bytes()))),
        _ => None,
    };

    let public_values_raw = proof.public_values.raw();
    let public_values_hash = format!("0x{}", hex::encode(proof.public_values.hash()));
    let public_values_hash_bn254 = format!(
        "0x{}",
        proof.public_values.hash_bn254().to_str_radix(16)
    );

    let artifact = ProofArtifact {
        program_vkey,
        proof_kind: proof_kind.as_str().to_string(),
        proof_bytes,
        public_values_raw,
        public_values_hash,
        public_values_hash_bn254,
        output,
    };

    let json_bytes = serde_json::to_vec_pretty(&artifact)
        .map_err(|err| format!("failed to serialize proof artifact: {err}"))?;
    fs::write(&proof_json_path, json_bytes)
        .map_err(|err| format!("failed to write proof artifact: {err}"))?;

    println!("Proof saved to {}", proof_path.display());
    println!("Proof artifact saved to {}", proof_json_path.display());
    Ok(())
}
