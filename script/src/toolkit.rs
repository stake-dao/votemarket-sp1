//! Python toolkit integration for proof generation.

use alloy_primitives::Address;
use serde::Deserialize;
use std::{
    env, fs,
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use crate::helpers::deserialize_address;
use crate::types::HostInput;

const TOOLKIT_ADAPTER: &str = "toolkit_adapter.py";

/// Cap on the toolkit child's stdout, enforced as it is read so an oversized
/// bundle is refused before `serde_json` ever sees it. A real bundle is a few KB.
pub const MAX_TOOLKIT_STDOUT_BYTES: usize = 8 * 1024 * 1024;

/// Cap on how much child stderr is shown in an error message. Stderr is attacker-
/// influenced text that lands in logs, so it is bounded and redacted, never echoed
/// whole.
pub const MAX_TOOLKIT_STDERR_BYTES: usize = 4 * 1024;

/// How much child stderr is captured, as opposed to shown.
///
/// Deliberately larger than the display cap: redaction runs over the whole capture
/// and truncation happens afterwards, so a credential-bearing URL sitting near the
/// display edge is still matched and scrubbed as a whole. Truncating first would
/// bisect such a URL, leaving a prefix that matches no replacement and carries part
/// of the API key into the error. Python tracebacks routinely run past 4 KB before
/// the final line that echoes the URL, so this is the common case, not a corner.
const CAPTURE_TOOLKIT_STDERR_BYTES: usize = 4 * MAX_TOOLKIT_STDERR_BYTES;

/// Env vars the toolkit child is allowed to inherit. Everything else is dropped by
/// `env_clear`, so a compromised or over-curious toolkit cannot read
/// `NETWORK_PRIVATE_KEY` (or any other secret) out of the prover's environment.
///
/// This is a closed allowlist, not a denylist of known-bad names: a new secret in
/// the prover's environment is excluded by default rather than by remembering to
/// ban it. The chain's RPC var and `PYTHONPATH` are the toolkit's actual inputs;
/// the rest are what a Python process needs to reach the network at all, and
/// scrubbing them turns a proxied or custom-CA environment into an opaque
/// connection failure with no hint that this scrub is the cause.
///
/// What this does NOT claim: the entries are not all secret-free. A proxy URL can
/// carry credentials in its userinfo, and the RPC URL carries an API key. Both are
/// credentials the toolkit needs in order to do its job, and it is handed them
/// deliberately. The line this draws is narrower and worth stating exactly: the
/// signing key (`NETWORK_PRIVATE_KEY`) is the one credential the toolkit has no use
/// for, and it never reaches the child's environment. It remains readable from
/// `script/.env` on disk, which this cannot address (see `run_toolkit`).
fn allowlisted_child_env(rpc_env_name: &str, rpc_url: &str) -> Vec<(String, String)> {
    /// `HOME` is load-bearing in the Docker image: the toolkit is installed with
    /// `pip install --user`, so Python resolves its site-packages under `~`.
    const PASSTHROUGH: [&str; 7] = [
        "PATH",
        "HOME",
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "NO_PROXY",
        "REQUESTS_CA_BUNDLE",
        "SSL_CERT_FILE",
    ];

    let mut allowed = vec![(rpc_env_name.to_string(), rpc_url.to_string())];
    for name in PASSTHROUGH {
        if let Ok(value) = env::var(name) {
            allowed.push((name.to_string(), value));
        }
    }
    if let Ok(toolkit_root) = env::var("TOOLKIT_ROOT") {
        allowed.push(("PYTHONPATH".to_string(), toolkit_root));
    }
    allowed
}

/// Replace the RPC URL (and its path+query on its own) with placeholders in child
/// stderr, and bound its length, before it is embedded in an error.
///
/// The toolkit is handed the RPC URL, so its own diagnostics can echo the
/// credential back at us. This scrubs the credential in the forms the toolkit is
/// actually observed to print: the URL verbatim, or the path+query of a derived
/// target. It is substring replacement, not a general secret detector, so a
/// percent-encoded or otherwise transformed rendering would survive it. The
/// credential is one the caller already holds, so this bounds accidental disclosure
/// in logs rather than defending against a toolkit deliberately exfiltrating it,
/// which nothing on this side of the process boundary can prevent.
fn redact_child_stderr(stderr: &[u8], rpc_url: &str) -> String {
    // Redact over the whole capture, before any truncation (see the capture cap).
    let text = String::from_utf8_lossy(stderr);
    let mut redacted = text.replace(rpc_url, "<redacted-rpc-url>");

    // Also scrub the URL's path+query on its own: the toolkit may print a derived
    // form (a retry target, a redirect) rather than the exact string we passed.
    // Skip a short path: a bare `/` or `/v2` holds no credential but appears all
    // over ordinary text, and replacing it would rewrite every slash in the output.
    if let Some((_, path_and_query)) = split_url_origin(rpc_url) {
        if path_and_query.len() >= MIN_REDACTABLE_PATH {
            redacted = redacted.replace(path_and_query, "/<redacted>");
        }
    }

    if redacted.len() > MAX_TOOLKIT_STDERR_BYTES {
        // Cut on a char boundary: the capture is arbitrary bytes from the child.
        let mut cut = MAX_TOOLKIT_STDERR_BYTES;
        while cut > 0 && !redacted.is_char_boundary(cut) {
            cut -= 1;
        }
        redacted.truncate(cut);
        redacted.push_str("... <truncated>");
    }
    redacted
}

/// Shortest URL path worth scrubbing on its own. See the RPC client's copy.
const MIN_REDACTABLE_PATH: usize = 8;

/// Split a URL into its `scheme://host[:port]` origin and the remaining path+query.
fn split_url_origin(url: &str) -> Option<(&str, &str)> {
    let scheme_end = url.find("://")? + 3;
    let rest = &url[scheme_end..];
    match rest.find('/') {
        Some(idx) => Some((&url[..scheme_end + idx], &rest[idx..])),
        None => Some((url, "")),
    }
}

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

/// A proof bundle as emitted by `toolkit_adapter.py`.
///
/// The context fields are mandatory and are cross-checked against the caller's
/// `HostInput` by `verify_bundle_context`. They previously carried `_` prefixes,
/// which matched no key the adapter emits, so they silently deserialized to `None`
/// and no mismatch could ever be caught. The names here must track the adapter's
/// output keys.
#[derive(Debug, Deserialize)]
pub struct ToolkitProofBundle {
    pub protocol: String,
    pub chain_id: u64,
    pub block_number: u64,
    pub epoch: u64,
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
///
/// The child runs with a scrubbed environment (see `allowlisted_child_env`) and a
/// bounded stdout, and the returned bundle is cross-checked against the caller's
/// own context before it can reach the prover.
pub fn run_toolkit(
    input_path: &Path,
    rpc_env_name: &str,
    rpc_url: &str,
    host_input: &HostInput,
    epoch: u64,
) -> Result<ToolkitProofBundle, String> {
    let adapter = Path::new(env!("CARGO_MANIFEST_DIR")).join(TOOLKIT_ADAPTER);

    let mut command = Command::new(resolve_python_bin());
    command.arg(adapter).arg(input_path);
    command.env_clear();
    command.envs(allowlisted_child_env(rpc_env_name, rpc_url));

    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| format!("toolkit execution failed: {err}"))?;

    // Drain stderr on its own thread. Reading stdout to completion first would
    // deadlock against a child that fills the stderr pipe while we are still
    // reading, which is exactly what a chatty failure looks like.
    let mut stderr_pipe = child.stderr.take().expect("stderr is piped");
    let stderr_reader = std::thread::spawn(move || {
        let mut buffer = Vec::new();
        let _ = stderr_pipe
            .by_ref()
            .take(CAPTURE_TOOLKIT_STDERR_BYTES as u64)
            .read_to_end(&mut buffer);
        // Keep draining past the cap so the child never blocks on a full pipe.
        let _ = std::io::copy(&mut stderr_pipe, &mut std::io::sink());
        buffer
    });

    // Read one byte past the cap: enough to know the bundle is oversized, without
    // buffering however much more the child wanted to send.
    let mut stdout_pipe = child.stdout.take().expect("stdout is piped");
    let mut stdout = Vec::new();
    let read_result = stdout_pipe
        .by_ref()
        .take(MAX_TOOLKIT_STDOUT_BYTES as u64 + 1)
        .read_to_end(&mut stdout);
    let oversized = stdout.len() > MAX_TOOLKIT_STDOUT_BYTES;

    if oversized {
        // Kill rather than drain: a child streaming without end would otherwise hold
        // the prover here forever, which is the very thing the cap exists to stop.
        // Dropping the pipes lets the child die on SIGPIPE even if the kill races.
        let _ = child.kill();
        let _ = child.wait();
        drop(stdout_pipe);
        let _ = stderr_reader.join();
        return Err(format!(
            "toolkit output too large: exceeds the {MAX_TOOLKIT_STDOUT_BYTES} byte cap"
        ));
    }

    let status = child
        .wait()
        .map_err(|err| format!("toolkit wait failed: {err}"))?;
    let stderr = stderr_reader
        .join()
        .map_err(|_| "toolkit stderr reader panicked".to_string())?;

    if !status.success() {
        return Err(format!(
            "toolkit exited with status {}: {}",
            status,
            redact_child_stderr(&stderr, rpc_url)
        ));
    }
    read_result.map_err(|err| format!("failed to read toolkit output: {err}"))?;

    let bundle: ToolkitProofBundle = serde_json::from_slice(&stdout)
        .map_err(|err| format!("failed to parse toolkit output: {err}"))?;
    verify_bundle_context(&bundle, host_input, epoch)?;
    Ok(bundle)
}

/// Reject a bundle whose self-reported context disagrees with what we asked for.
///
/// The caller's `HostInput` is the authority: the bundle's own fields are only a
/// claim by the child. This is a wiring check (a stale file, a toolkit that
/// silently answered a different block) rather than a trust boundary, since the
/// proofs themselves are bound by the state root the guest verifies against.
fn verify_bundle_context(
    bundle: &ToolkitProofBundle,
    host_input: &HostInput,
    epoch: u64,
) -> Result<(), String> {
    let block_number = host_input
        .block_number
        .ok_or_else(|| "block number must be resolved before running the toolkit".to_string())?;

    if !bundle
        .protocol
        .eq_ignore_ascii_case(&host_input.protocol_name)
    {
        return Err(format!(
            "toolkit bundle protocol mismatch: requested {}, got {}",
            host_input.protocol_name, bundle.protocol
        ));
    }
    if bundle.chain_id != host_input.chain_id {
        return Err(format!(
            "toolkit bundle chain_id mismatch: requested {}, got {}",
            host_input.chain_id, bundle.chain_id
        ));
    }
    if bundle.block_number != block_number {
        return Err(format!(
            "toolkit bundle block_number mismatch: requested {block_number}, got {}",
            bundle.block_number
        ));
    }
    if bundle.epoch != epoch {
        return Err(format!(
            "toolkit bundle epoch mismatch: requested {epoch}, got {}",
            bundle.epoch
        ));
    }
    Ok(())
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
                "gauge": "{TEST_GAUGE}",
                "gauge_controller_proof": "0xf851...",
                "point_data_proof": "0xc1c0..."
            }}"#
        );
        let proof: ToolkitGaugeProof = serde_json::from_str(&json).unwrap();
        assert_eq!(
            proof.gauge.to_string().to_lowercase(),
            TEST_GAUGE.to_lowercase()
        );
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
                "account": "{TEST_ACCOUNT}",
                "gauge": "{TEST_GAUGE}",
                "account_proof": "0xf851...",
                "storage_proof": "0xc1c0..."
            }}"#
        );
        let proof: ToolkitUserProof = serde_json::from_str(&json).unwrap();
        assert_eq!(
            proof.account.to_string().to_lowercase(),
            TEST_ACCOUNT.to_lowercase()
        );
        assert_eq!(
            proof.gauge.to_string().to_lowercase(),
            TEST_GAUGE.to_lowercase()
        );
        assert_eq!(proof.account_proof, "0xf851...");
        assert_eq!(proof.storage_proof, "0xc1c0...");
    }

    ///////////////////////////////////////////////
    // TOOLKIT PROOF BUNDLE DESERIALIZATION TESTS
    ///////////////////////////////////////////////

    const TEST_BLOCK: u64 = 21134723;
    const TEST_EPOCH: u64 = 1730937600;

    /// The exact key shape `toolkit_adapter.py` emits (see its `bundle` dict), with
    /// the proof lists left empty.
    fn adapter_bundle_json(protocol: &str, chain_id: u64, block_number: u64, epoch: u64) -> String {
        format!(
            r#"{{
                "protocol": "{protocol}",
                "chain_id": {chain_id},
                "block_number": {block_number},
                "epoch": {epoch},
                "gauge_proofs": [],
                "user_proofs": []
            }}"#
        )
    }

    fn test_host_input() -> HostInput {
        HostInput {
            chain_id: 1,
            block_number: Some(TEST_BLOCK),
            epoch_override: Some(TEST_EPOCH),
            protocol: crate::protocol::Protocol::Curve,
            protocol_name: "curve".to_string(),
            gauge_controller: crate::protocol::Protocol::Curve.gauge_controller().unwrap(),
            slots: crate::protocol::Protocol::Curve.base_slots(),
            requests: vec![],
        }
    }

    #[test]
    fn test_toolkit_proof_bundle_empty() {
        let bundle: ToolkitProofBundle =
            serde_json::from_str(&adapter_bundle_json("curve", 1, TEST_BLOCK, TEST_EPOCH)).unwrap();
        assert!(bundle.gauge_proofs.is_empty());
        assert!(bundle.user_proofs.is_empty());
    }

    // The context fields must populate from the adapter's real keys. Before the
    // rename they were `_protocol`/`_block_number`/`_epoch`, which match nothing the
    // adapter emits, so every bundle parsed with the context silently absent.
    #[test]
    fn test_toolkit_proof_bundle_context_populates_from_adapter_keys() {
        let bundle: ToolkitProofBundle =
            serde_json::from_str(&adapter_bundle_json("curve", 1, TEST_BLOCK, TEST_EPOCH)).unwrap();
        assert_eq!(bundle.protocol, "curve");
        assert_eq!(bundle.chain_id, 1);
        assert_eq!(bundle.block_number, TEST_BLOCK);
        assert_eq!(bundle.epoch, TEST_EPOCH);
    }

    #[test]
    fn test_toolkit_proof_bundle_full() {
        let json = format!(
            r#"{{
                "protocol": "curve",
                "chain_id": 1,
                "block_number": {TEST_BLOCK},
                "epoch": {TEST_EPOCH},
                "gauge_proofs": [
                    {{
                        "gauge": "{TEST_GAUGE}",
                        "gauge_controller_proof": "0xf851...",
                        "point_data_proof": "0xc1c0..."
                    }}
                ],
                "user_proofs": [
                    {{
                        "account": "{TEST_ACCOUNT}",
                        "gauge": "{TEST_GAUGE}",
                        "account_proof": "0xf851...",
                        "storage_proof": "0xc1c0..."
                    }}
                ]
            }}"#
        );
        let bundle: ToolkitProofBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(bundle.gauge_proofs.len(), 1);
        assert_eq!(bundle.user_proofs.len(), 1);
    }

    // A bundle with no context at all is now a hard parse error rather than a
    // silently-empty context.
    #[test]
    fn test_toolkit_proof_bundle_missing_context_is_rejected() {
        let result: Result<ToolkitProofBundle, _> = serde_json::from_str(r#"{}"#);
        assert!(result.is_err());

        // Each context field is individually mandatory.
        for missing in ["protocol", "chain_id", "block_number", "epoch"] {
            let mut value: serde_json::Value =
                serde_json::from_str(&adapter_bundle_json("curve", 1, TEST_BLOCK, TEST_EPOCH))
                    .unwrap();
            value.as_object_mut().unwrap().remove(missing);
            let result: Result<ToolkitProofBundle, _> = serde_json::from_value(value);
            assert!(result.is_err(), "missing {missing} must be rejected");
        }
    }

    ///////////////////////////////////////////////
    // BUNDLE CONTEXT CROSS-CHECK TESTS
    ///////////////////////////////////////////////

    #[test]
    fn test_verify_bundle_context_accepts_matching_context() {
        let bundle: ToolkitProofBundle =
            serde_json::from_str(&adapter_bundle_json("curve", 1, TEST_BLOCK, TEST_EPOCH)).unwrap();
        assert!(verify_bundle_context(&bundle, &test_host_input(), TEST_EPOCH).is_ok());
    }

    #[test]
    fn test_verify_bundle_context_is_case_insensitive_on_protocol() {
        let bundle: ToolkitProofBundle =
            serde_json::from_str(&adapter_bundle_json("CURVE", 1, TEST_BLOCK, TEST_EPOCH)).unwrap();
        assert!(verify_bundle_context(&bundle, &test_host_input(), TEST_EPOCH).is_ok());
    }

    #[test]
    fn test_verify_bundle_context_rejects_each_mismatch() {
        let cases = [
            (
                adapter_bundle_json("balancer", 1, TEST_BLOCK, TEST_EPOCH),
                "protocol",
            ),
            (
                adapter_bundle_json("curve", 42161, TEST_BLOCK, TEST_EPOCH),
                "chain_id",
            ),
            (
                adapter_bundle_json("curve", 1, TEST_BLOCK + 1, TEST_EPOCH),
                "block_number",
            ),
            (
                adapter_bundle_json("curve", 1, TEST_BLOCK, TEST_EPOCH + 604800),
                "epoch",
            ),
        ];
        for (json, field) in cases {
            let bundle: ToolkitProofBundle = serde_json::from_str(&json).unwrap();
            let err = verify_bundle_context(&bundle, &test_host_input(), TEST_EPOCH)
                .expect_err("mismatched {field} must be rejected");
            assert!(err.contains(field), "expected {field} in error, got: {err}");
        }
    }

    ///////////////////////////////////////////////
    // STDOUT BOUND TESTS
    ///////////////////////////////////////////////

    // The cap only means something if it also stops the read. A child that streams
    // without end must be killed, not drained: draining to EOF would hold the prover
    // here forever, which is exactly the hang the cap exists to prevent. This test
    // deadlocks on a regression rather than failing, which is the honest signal.
    #[test]
    fn test_endless_toolkit_output_is_killed_not_drained() {
        let dir = std::env::temp_dir().join("endless-toolkit-stdout");
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("endless.sh");
        std::fs::write(
            &script,
            "#!/bin/sh\nwhile :; do printf 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'; done\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let mut command = Command::new("/bin/sh");
        command.arg(&script);
        command.env_clear();
        command.envs(allowlisted_child_env(
            "ETHEREUM_MAINNET_RPC_URL",
            "https://x/y",
        ));

        let mut child = command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();

        let mut stdout_pipe = child.stdout.take().unwrap();
        let mut stdout = Vec::new();
        stdout_pipe
            .by_ref()
            .take(MAX_TOOLKIT_STDOUT_BYTES as u64 + 1)
            .read_to_end(&mut stdout)
            .unwrap();

        assert!(
            stdout.len() > MAX_TOOLKIT_STDOUT_BYTES,
            "cap must be crossed"
        );

        // The production path kills here; mirror it and prove the child is reaped
        // rather than left streaming.
        child.kill().unwrap();
        drop(stdout_pipe);
        let status = child.wait().unwrap();
        assert!(!status.success(), "killed child must not report success");

        let _ = std::fs::remove_file(&script);
    }

    ///////////////////////////////////////////////
    // CHILD ENV ISOLATION TESTS
    ///////////////////////////////////////////////

    // The prover process holds NETWORK_PRIVATE_KEY in its own env (dotenv loads it),
    // and the toolkit has no business seeing it.
    #[test]
    fn test_child_env_allowlist_excludes_secrets() {
        let allowed = allowlisted_child_env("ETHEREUM_MAINNET_RPC_URL", "https://rpc.example/key");
        let names: Vec<&str> = allowed.iter().map(|(name, _)| name.as_str()).collect();

        assert!(names.contains(&"ETHEREUM_MAINNET_RPC_URL"));
        assert!(!names.contains(&"NETWORK_PRIVATE_KEY"));

        // The allowlist must stay a closed set, not a denylist of known-bad names:
        // that is what makes a future secret in the prover's env excluded by
        // default rather than by someone remembering to ban it.
        const EXPECTED: [&str; 9] = [
            "ETHEREUM_MAINNET_RPC_URL",
            "PATH",
            "HOME",
            "HTTPS_PROXY",
            "HTTP_PROXY",
            "NO_PROXY",
            "REQUESTS_CA_BUNDLE",
            "SSL_CERT_FILE",
            "PYTHONPATH",
        ];
        for name in &names {
            assert!(
                EXPECTED.contains(name),
                "unexpected variable {name} reaches the toolkit child"
            );
        }
    }

    ///////////////////////////////////////////////
    // STDERR REDACTION TESTS
    ///////////////////////////////////////////////

    #[test]
    fn test_redact_child_stderr_scrubs_rpc_credential() {
        let rpc_url = "https://eth-mainnet.example.com/v2/super-secret-key";
        let stderr = format!("requests.exceptions.HTTPError: 401 for url: {rpc_url}\n");
        let redacted = redact_child_stderr(stderr.as_bytes(), rpc_url);

        assert!(!redacted.contains("super-secret-key"), "{redacted}");
        assert!(redacted.contains("<redacted"));
    }

    // The toolkit may print a derived form of the URL rather than the exact string,
    // so the path is scrubbed on its own too.
    #[test]
    fn test_redact_child_stderr_scrubs_derived_url_path() {
        let rpc_url = "https://eth-mainnet.example.com/v2/super-secret-key";
        let stderr = b"retrying POST /v2/super-secret-key after 500\n";
        let redacted = redact_child_stderr(stderr, rpc_url);

        assert!(!redacted.contains("super-secret-key"), "{redacted}");
    }

    #[test]
    fn test_redact_child_stderr_is_length_bounded() {
        let rpc_url = "https://eth-mainnet.example.com/v2/key";
        let stderr = vec![b'x'; CAPTURE_TOOLKIT_STDERR_BYTES];
        let redacted = redact_child_stderr(&stderr, rpc_url);

        assert!(redacted.len() < MAX_TOOLKIT_STDERR_BYTES + 64);
        assert!(redacted.ends_with("<truncated>"));
    }

    // Redaction must run over the whole capture, not the displayed window. A URL
    // straddling the display edge would otherwise match neither replacement, and
    // the surviving prefix carries part of the API key. A long Python traceback
    // ending in the URL is the ordinary shape of this, not a contrived one.
    #[test]
    fn test_redact_child_stderr_scrubs_url_straddling_the_display_edge() {
        const KEY: &str = "super-secret-key-material";
        let rpc_url = format!("https://eth-mainnet.example.com/v2/{KEY}");

        // Land the URL so it begins just before the display cap and runs past it.
        let filler_len = MAX_TOOLKIT_STDERR_BYTES - 10;
        let stderr = format!("{}{rpc_url}\n", "t".repeat(filler_len));
        assert!(
            stderr.len() > MAX_TOOLKIT_STDERR_BYTES,
            "URL must cross the edge"
        );

        let redacted = redact_child_stderr(stderr.as_bytes(), &rpc_url);
        assert!(
            !redacted.contains("super-secret"),
            "credential prefix survived the display-edge cut: {}",
            &redacted[redacted.len().saturating_sub(120)..]
        );
    }

    #[test]
    fn test_split_url_origin() {
        assert_eq!(
            split_url_origin("https://host.example/v2/key"),
            Some(("https://host.example", "/v2/key"))
        );
        assert_eq!(
            split_url_origin("https://host.example"),
            Some(("https://host.example", ""))
        );
        assert_eq!(split_url_origin("not-a-url"), None);
    }
}
