//! Python toolkit integration for proof generation.

use alloy_primitives::Address;
use serde::Deserialize;
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

use crate::helpers::deserialize_address;
use crate::types::HostInput;

const TOOLKIT_ADAPTER: &str = "toolkit_adapter.py";

///////////////////////////////////////////////
// TOOLKIT TYPES
///////////////////////////////////////////////

#[derive(Debug, Deserialize)]
pub struct ToolkitGaugeProof {
    #[serde(deserialize_with = "deserialize_address")]
    pub gauge: Address,
    #[serde(rename = "gauge_controller_proof")]
    pub gauge_controller_proof: String,
    #[serde(rename = "point_data_proof")]
    pub point_data_proof: String,
}

#[derive(Debug, Deserialize)]
pub struct ToolkitUserProof {
    #[serde(deserialize_with = "deserialize_address")]
    pub account: Address,
    #[serde(deserialize_with = "deserialize_address")]
    pub gauge: Address,
    #[serde(rename = "account_proof")]
    pub account_proof: String,
    #[serde(rename = "storage_proof")]
    pub storage_proof: String,
}

#[derive(Debug, Deserialize)]
pub struct ToolkitProofBundle {
    #[serde(default)]
    pub _protocol: Option<String>,
    #[serde(default)]
    pub _block_number: Option<u64>,
    #[serde(default)]
    pub _epoch: Option<u64>,
    #[serde(default)]
    pub gauge_proofs: Vec<ToolkitGaugeProof>,
    #[serde(default)]
    pub user_proofs: Vec<ToolkitUserProof>,
}

///////////////////////////////////////////////
// TOOLKIT FUNCTIONS
///////////////////////////////////////////////

/// Ensure an input JSON file exists for the toolkit.
/// If INPUT_JSON env var is set, use that path. Otherwise, create a new file.
pub fn ensure_input_json(input: &HostInput, epoch: u64) -> Result<PathBuf, String> {
    if let Ok(path) = env::var("INPUT_JSON") {
        return Ok(PathBuf::from(path));
    }

    let output_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("output");
    fs::create_dir_all(&output_dir).map_err(|err| format!("failed to create output dir: {err}"))?;
    let path = output_dir.join("host_input.json");
    let payload = serde_json::to_string_pretty(&input.to_json_value(epoch))
        .map_err(|err| format!("failed to serialize host input: {err}"))?;
    fs::write(&path, payload).map_err(|err| format!("failed to write host input: {err}"))?;
    Ok(path)
}

/// Run the Python toolkit adapter to generate proofs.
pub fn run_toolkit(
    input_path: &Path,
    rpc_env_name: &str,
    rpc_url: &str,
) -> Result<ToolkitProofBundle, String> {
    let toolkit_root = env::var("TOOLKIT_ROOT").ok().map(PathBuf::from);
    let adapter = Path::new(env!("CARGO_MANIFEST_DIR")).join(TOOLKIT_ADAPTER);

    let mut command = Command::new(resolve_python_bin());
    command.arg(adapter).arg(input_path);
    command.env(rpc_env_name, rpc_url);
    if let Some(toolkit_root) = toolkit_root {
        command.env("PYTHONPATH", toolkit_root);
    }

    let output = command
        .output()
        .map_err(|err| format!("toolkit execution failed: {err}"))?;

    if !output.status.success() {
        return Err(format!(
            "toolkit exited with status {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    serde_json::from_slice(&output.stdout)
        .map_err(|err| format!("failed to parse toolkit output: {err}"))
}

/// Resolve the Python binary to use for the toolkit.
fn resolve_python_bin() -> String {
    if let Ok(python) = env::var("PYTHON_BIN") {
        return python;
    }

    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(PathBuf::from);
    let root = root.unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf());
    let candidates = [
        root.join(".venv/bin/python"),
        root.join(".venv/bin/python3"),
        root.join(".venv/Scripts/python.exe"),
    ];

    for candidate in candidates {
        if candidate.exists() {
            return candidate.to_string_lossy().to_string();
        }
    }

    "python3".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test fixtures
    const TEST_GAUGE: &str = "0x26f7786de3e6d9bd37fcf47be6f2bc455a21b74a";
    const TEST_ACCOUNT: &str = "0xfac2f11ba2577d5122dc1ec5301d35b16688251e";

    ///////////////////////////////////////////////
    // TOOLKIT GAUGE PROOF DESERIALIZATION TESTS
    ///////////////////////////////////////////////

    #[test]
    fn test_toolkit_gauge_proof_deserialize() {
        let json = format!(
            r#"{{
                "gauge": "{}",
                "gauge_controller_proof": "0xf851...",
                "point_data_proof": "0xc1c0..."
            }}"#,
            TEST_GAUGE
        );
        let proof: ToolkitGaugeProof = serde_json::from_str(&json).unwrap();
        assert_eq!(proof.gauge.to_string().to_lowercase(), TEST_GAUGE.to_lowercase());
        assert_eq!(proof.gauge_controller_proof, "0xf851...");
        assert_eq!(proof.point_data_proof, "0xc1c0...");
    }

    ///////////////////////////////////////////////
    // TOOLKIT USER PROOF DESERIALIZATION TESTS
    ///////////////////////////////////////////////

    #[test]
    fn test_toolkit_user_proof_deserialize() {
        let json = format!(
            r#"{{
                "account": "{}",
                "gauge": "{}",
                "account_proof": "0xf851...",
                "storage_proof": "0xc1c0..."
            }}"#,
            TEST_ACCOUNT, TEST_GAUGE
        );
        let proof: ToolkitUserProof = serde_json::from_str(&json).unwrap();
        assert_eq!(proof.account.to_string().to_lowercase(), TEST_ACCOUNT.to_lowercase());
        assert_eq!(proof.gauge.to_string().to_lowercase(), TEST_GAUGE.to_lowercase());
        assert_eq!(proof.account_proof, "0xf851...");
        assert_eq!(proof.storage_proof, "0xc1c0...");
    }

    ///////////////////////////////////////////////
    // TOOLKIT PROOF BUNDLE DESERIALIZATION TESTS
    ///////////////////////////////////////////////

    #[test]
    fn test_toolkit_proof_bundle_empty() {
        let json = r#"{
            "gauge_proofs": [],
            "user_proofs": []
        }"#;
        let bundle: ToolkitProofBundle = serde_json::from_str(json).unwrap();
        assert!(bundle.gauge_proofs.is_empty());
        assert!(bundle.user_proofs.is_empty());
    }

    #[test]
    fn test_toolkit_proof_bundle_with_optional_fields() {
        let json = r#"{
            "_protocol": "curve",
            "_block_number": 21134723,
            "_epoch": 1730937600,
            "gauge_proofs": [],
            "user_proofs": []
        }"#;
        let bundle: ToolkitProofBundle = serde_json::from_str(json).unwrap();
        assert_eq!(bundle._protocol, Some("curve".to_string()));
        assert_eq!(bundle._block_number, Some(21134723));
        assert_eq!(bundle._epoch, Some(1730937600));
    }

    #[test]
    fn test_toolkit_proof_bundle_full() {
        let json = format!(
            r#"{{
                "gauge_proofs": [
                    {{
                        "gauge": "{}",
                        "gauge_controller_proof": "0xf851...",
                        "point_data_proof": "0xc1c0..."
                    }}
                ],
                "user_proofs": [
                    {{
                        "account": "{}",
                        "gauge": "{}",
                        "account_proof": "0xf851...",
                        "storage_proof": "0xc1c0..."
                    }}
                ]
            }}"#,
            TEST_GAUGE, TEST_ACCOUNT, TEST_GAUGE
        );
        let bundle: ToolkitProofBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(bundle.gauge_proofs.len(), 1);
        assert_eq!(bundle.user_proofs.len(), 1);
    }

    #[test]
    fn test_toolkit_proof_bundle_defaults_missing_fields() {
        // Test that missing optional fields default correctly
        let json = r#"{}"#;
        let bundle: ToolkitProofBundle = serde_json::from_str(json).unwrap();
        assert!(bundle._protocol.is_none());
        assert!(bundle._block_number.is_none());
        assert!(bundle._epoch.is_none());
        assert!(bundle.gauge_proofs.is_empty());
        assert!(bundle.user_proofs.is_empty());
    }
}
