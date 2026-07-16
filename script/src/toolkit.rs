//! Python toolkit integration for proof generation.

use alloy_primitives::Address;
use serde::Deserialize;
use std::{
    env, fs,
    io::Read,
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    time::{Duration, Instant},
};

use crate::helpers::{deserialize_address, parse_positive_u64_env};
use crate::types::HostInput;

const TOOLKIT_ADAPTER: &str = "toolkit_adapter.py";

/// Wall-clock ceiling on the toolkit child, overridable via `TOOLKIT_TIMEOUT_SECS`.
///
/// Generous by design and env-tunable because legitimate runtime scales with the
/// batch size and the RPC's mood, neither of which the per-call RPC timeouts bound:
/// one toolkit run issues many calls.
const DEFAULT_TOOLKIT_TIMEOUT_SECS: u64 = 600;

/// How often the supervisor re-checks the readers, the size flag, and the deadline.
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// How long the supervisor waits for the reader threads after deciding to stop.
///
/// A group kill releases every pipe immediately, so this normally elapses in
/// microseconds. It exists for the descendant that escaped the group (its own
/// `setsid`) and still holds a write end: without a bound, such a process could
/// re-hang the parent on the way out, which is the very hang the deadline exists
/// to prevent. On expiry the reader is abandoned rather than joined.
const READER_GRACE: Duration = Duration::from_secs(5);

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
    let deadline = Duration::from_secs(
        parse_positive_u64_env("TOOLKIT_TIMEOUT_SECS")?.unwrap_or(DEFAULT_TOOLKIT_TIMEOUT_SECS),
    );

    let mut command = Command::new(resolve_python_bin());
    command.arg(adapter).arg(input_path);
    command.env_clear();
    command.envs(allowlisted_child_env(rpc_env_name, rpc_url));

    let outcome = supervise_child(&mut command, deadline, rpc_url)?;

    if !outcome.status.success() {
        return Err(format!(
            "toolkit exited with status {}: {}",
            outcome.status,
            redact_child_stderr(&outcome.stderr, rpc_url)
        ));
    }
    // Deferred deliberately: a child that failed should report its own stderr
    // rather than whatever the read of its truncated stdout happened to return.
    outcome.stdout_read?;

    let bundle: ToolkitProofBundle = serde_json::from_slice(&outcome.stdout)
        .map_err(|err| format!("failed to parse toolkit output: {err}"))?;
    verify_bundle_context(&bundle, host_input, epoch)?;
    Ok(bundle)
}

/// What a supervised child produced, once it is known to have finished.
#[derive(Debug)]
struct ChildOutcome {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    status: ExitStatus,
    /// Held rather than resolved, so the caller keeps the stderr-before-read-error
    /// ordering above.
    stdout_read: Result<(), String>,
}

/// Run a child to completion under a wall-clock deadline and a stdout size cap.
///
/// The caller owns the program, arguments, and environment; this owns the pipes,
/// the process group, the kill decision, and the single reap.
///
/// Two invariants shape the loop below, and both are load-bearing:
///
/// 1. **Kill the group, not the child.** A grandchild that inherits stdout holds
///    the pipe's write end, so the pipe does not reach EOF when the direct child
///    dies and a reader blocks for as long as the grandchild lives (measured at
///    5.71s against a trivial case; unbounded in general).
/// 2. **Never signal the group after reaping the leader.** The leader's zombie is
///    what pins the pid, and therefore the pgid, against reuse. `try_wait` and
///    `wait` both reap, so a `killpg` issued after either could land on a
///    recycled, unrelated group. Hence phase 1 never touches the child, and phase
///    2 only reaps on a path that never kills.
fn supervise_child(
    command: &mut Command,
    deadline: Duration,
    rpc_url: &str,
) -> Result<ChildOutcome, String> {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }

    // Install before spawning so the disposition is never the default one while a
    // child exists. `process_group(0)` takes the child out of the terminal's
    // foreground group the instant it exists, so Ctrl-C reaches only the prover and
    // the prover is the deadline's sole enforcer.
    //
    // What this does NOT claim: it does not close the orphan window, it only
    // narrows what runs inside it. The handler no-ops until `arm_signal_forwarding`
    // publishes the pid, so a signal landing between the child's birth and that
    // store still re-raises and kills the prover with the child already detached,
    // which is the same orphan a late install would have produced. The window is
    // irreducible here: nothing can signal a process whose pid the parent has not
    // been told yet, and masking would not help, since a process-directed signal
    // is simply delivered to one of the tokio worker threads instead. It is the
    // tail of one `spawn` once per run, and the Docker path (every `just prove`
    // recipe) bounds the escape with the container rather than with this handler.
    let _signals = SignalForwardGuard::install();

    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| format!("toolkit execution failed: {err}"))?;

    arm_signal_forwarding(&child);
    let oversized = Arc::new(AtomicBool::new(false));

    // Read one byte past the cap: enough to know the bundle is oversized, without
    // buffering however much more the child wanted to send. On its own thread
    // because the kill has to come from outside this blocking read.
    let mut stdout_pipe = child.stdout.take().expect("stdout is piped");
    let (stdout_tx, stdout_rx) = mpsc::channel();
    let stdout_flag = Arc::clone(&oversized);
    std::thread::spawn(move || {
        let mut buffer = Vec::new();
        let result = stdout_pipe
            .by_ref()
            .take(MAX_TOOLKIT_STDOUT_BYTES as u64 + 1)
            .read_to_end(&mut buffer);
        if buffer.len() > MAX_TOOLKIT_STDOUT_BYTES {
            stdout_flag.store(true, Ordering::SeqCst);
        }
        let _ = stdout_tx.send((result, buffer));
    });

    // Drain stderr on its own thread. Reading stdout to completion first would
    // deadlock against a child that fills the stderr pipe while we are still
    // reading, which is exactly what a chatty failure looks like.
    let mut stderr_pipe = child.stderr.take().expect("stderr is piped");
    let (stderr_tx, stderr_rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut buffer = Vec::new();
        let _ = stderr_pipe
            .by_ref()
            .take(CAPTURE_TOOLKIT_STDERR_BYTES as u64)
            .read_to_end(&mut buffer);
        // Keep draining past the cap so the child never blocks on a full pipe.
        let _ = std::io::copy(&mut stderr_pipe, &mut std::io::sink());
        let _ = stderr_tx.send(buffer);
    });

    let start = Instant::now();
    let mut stdout_slot = None;
    let mut stderr_slot = None;
    let mut timed_out = false;

    // Phase 1: readers outstanding. Both pipes at EOF is the only proof that every
    // write end is gone, the child's and its descendants' alike, so wait on the
    // readers rather than on the child. A lingering-but-legitimate grandchild
    // finishes here and the run completes normally.
    loop {
        if stdout_slot.is_none() {
            stdout_slot = stdout_rx.try_recv().ok();
        }
        if stderr_slot.is_none() {
            stderr_slot = stderr_rx.try_recv().ok();
        }
        // Order matters. The kill checks come first because a child can close both
        // pipes and stay alive: that fills both slots in a single tick, and leaving
        // via the readers would skip phase 2's guard and land on phase 3's
        // unconditional wait, which the child could then hold open for as long as it
        // liked. Every exit from this loop must either kill or hand phase 2 a child
        // it will bound.
        if oversized.load(Ordering::SeqCst) {
            kill_child_tree(&mut child);
            break;
        }
        if start.elapsed() >= deadline {
            kill_child_tree(&mut child);
            timed_out = true;
            break;
        }
        if stdout_slot.is_some() && stderr_slot.is_some() {
            break;
        }
        std::thread::sleep(POLL_INTERVAL);
    }

    // Phase 2: the pipes are at EOF, so the child is the only thing left that this
    // function still bounds (it may have closed its pipes and slept). `try_wait` is
    // safe now: it reaps only once the child has genuinely exited, and that path
    // issues no kill.
    //
    // EOF is proof that every write end is gone, not that every process is. A
    // descendant that closed the pipes and kept running outlives a successful run,
    // and no sweep can fix that here: learning the child succeeded means reaping
    // it, and after the reap invariant 2 forbids the `killpg` that would sweep the
    // group. Killing before the reap is not an option either, since a child still
    // doing legitimate work is indistinguishable at that point. A descendant that
    // `setsid`s out is already beyond `killpg` on every path. Containment for both
    // is the container the Docker recipes run in, not this loop.
    if !timed_out && !oversized.load(Ordering::SeqCst) {
        loop {
            match child.try_wait() {
                // Reaped: the pgid is no longer ours to signal, so disarm the
                // handler before anything else can fire it.
                Ok(Some(_)) => {
                    disarm_signal_forwarding();
                    break;
                }
                Ok(None) => {}
                Err(err) => return Err(format!("toolkit wait failed: {err}")),
            }
            if start.elapsed() >= deadline {
                kill_child_tree(&mut child);
                timed_out = true;
                break;
            }
            std::thread::sleep(POLL_INTERVAL);
        }
    }

    // Phase 3: collect and reap, always after the kill decision.
    //
    // One grace shared across both readers, not one each: waiting READER_GRACE per
    // pipe would put the worst case at deadline + 2 * grace and quietly break the
    // bound this function advertises.
    let grace_until = Instant::now() + READER_GRACE;
    let remaining = || grace_until.saturating_duration_since(Instant::now());
    let (stdout_read, stdout) = match stdout_slot {
        Some(value) => value,
        None => stdout_rx
            .recv_timeout(remaining())
            .unwrap_or_else(|_| (Ok(0), Vec::new())),
    };
    let stderr = match stderr_slot {
        Some(value) => value,
        None => stderr_rx.recv_timeout(remaining()).unwrap_or_default(),
    };
    // Disarm before the reap, not after: once the leader is reaped its pgid can be
    // recycled, and a signal arriving in the window between the reap and the
    // guard's drop would forward a SIGKILL to whatever inherited the number.
    disarm_signal_forwarding();
    let status = child
        .wait()
        .map_err(|err| format!("toolkit wait failed: {err}"))?;

    // Resolve the refusal from the size flag first, however the loop exited: a
    // child that overshoots the cap and then exits on its own must still report
    // the size refusal rather than let its truncated stdout reach the parser and
    // surface as an unhelpful decode error.
    if oversized.load(Ordering::SeqCst) {
        return Err(format!(
            "toolkit output too large: exceeds the {MAX_TOOLKIT_STDOUT_BYTES} byte cap"
        ));
    }
    if timed_out {
        return Err(format!(
            "toolkit timed out after {}s: {}",
            deadline.as_secs(),
            redact_child_stderr(&stderr, rpc_url)
        ));
    }

    Ok(ChildOutcome {
        stdout,
        stderr,
        status,
        stdout_read: stdout_read
            .map(|_| ())
            .map_err(|err| format!("failed to read toolkit output: {err}")),
    })
}

/// Kill the child and everything it spawned.
#[cfg(unix)]
fn kill_child_tree(child: &mut Child) {
    // SAFETY: the pgid is the child's own pid, because `process_group(0)` made it
    // a group leader, and the leader has not been reaped at any call site, so its
    // zombie still pins the pgid and this cannot reach an unrelated group.
    unsafe { libc::killpg(child.id() as libc::pid_t, libc::SIGKILL) };
}

/// Kill the child alone.
///
/// Descendants that inherited the pipes survive here and can hold them open, so
/// the reader grace rather than the kill is what bounds the wait. Unix gets the
/// stronger group kill above.
#[cfg(not(unix))]
fn kill_child_tree(child: &mut Child) {
    let _ = child.kill();
}

/// Forward a fatal terminal signal to the supervised process group.
///
/// `process_group(0)` is what lets the deadline reach descendants, but it also
/// takes the child out of the terminal's foreground group, so a Ctrl-C would
/// otherwise reach only the prover. The prover dying is precisely what removes the
/// deadline's enforcer, leaving the toolkit orphaned and unbounded, so the signal
/// has to be passed on before this process goes away.
#[cfg(unix)]
struct SignalForwardGuard {
    previous_int: libc::sighandler_t,
    previous_term: libc::sighandler_t,
}

#[cfg(unix)]
static SUPERVISED_PGID: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

/// Stop forwarding signals to the supervised group.
///
/// Must be called before the leader is reaped, never after: the reap releases the
/// pid, and therefore the pgid, for reuse, so a handler still holding the number
/// would signal whatever process group inherited it.
#[cfg(unix)]
fn disarm_signal_forwarding() {
    SUPERVISED_PGID.store(0, Ordering::SeqCst);
}

#[cfg(not(unix))]
fn disarm_signal_forwarding() {}

#[cfg(unix)]
extern "C" fn forward_fatal_signal(signum: libc::c_int) {
    let pgid = SUPERVISED_PGID.load(Ordering::SeqCst);
    if pgid > 0 {
        // SAFETY: `killpg` is async-signal-safe. A non-zero value means the
        // supervisor spawned the leader and has not reached its disarm, which
        // precedes every reap, so the pgid is still ours.
        //
        // Not claimed: the disarm cannot be atomic with the reap it guards, so a
        // signal landing in the few instructions between them would signal a pgid
        // just released. Closing that needs the reap under a signal mask; the
        // window it leaves is instructions wide rather than the seconds-long one
        // that arming across phase 3 would have left.
        unsafe { libc::killpg(pgid, libc::SIGKILL) };
    }
    // Restore the default and re-raise so the exit status is the ordinary
    // killed-by-signal one rather than something this handler invented.
    unsafe {
        libc::signal(signum, libc::SIG_DFL);
        libc::raise(signum);
    }
}

#[cfg(unix)]
impl SignalForwardGuard {
    fn install() -> Self {
        // SAFETY: installing a handler that only stores/loads an atomic and calls
        // async-signal-safe functions. The previous dispositions are restored on
        // drop, so nothing else's handler is clobbered beyond the child's life.
        unsafe {
            Self {
                previous_int: libc::signal(
                    libc::SIGINT,
                    forward_fatal_signal as *const () as libc::sighandler_t,
                ),
                previous_term: libc::signal(
                    libc::SIGTERM,
                    forward_fatal_signal as *const () as libc::sighandler_t,
                ),
            }
        }
    }
}

/// Start forwarding terminal signals to the child's group.
#[cfg(unix)]
fn arm_signal_forwarding(child: &Child) {
    SUPERVISED_PGID.store(child.id() as i32, Ordering::SeqCst);
}

#[cfg(not(unix))]
fn arm_signal_forwarding(_child: &Child) {}

#[cfg(unix)]
impl Drop for SignalForwardGuard {
    fn drop(&mut self) {
        // SAFETY: restoring the dispositions captured in `install`.
        unsafe {
            libc::signal(libc::SIGINT, self.previous_int);
            libc::signal(libc::SIGTERM, self.previous_term);
        }
        SUPERVISED_PGID.store(0, Ordering::SeqCst);
    }
}

#[cfg(not(unix))]
struct SignalForwardGuard;

#[cfg(not(unix))]
impl SignalForwardGuard {
    fn install() -> Self {
        Self
    }
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
    // SUPERVISION TESTS
    ///////////////////////////////////////////////

    /// Build a `/bin/sh -c` command wired like the real toolkit invocation.
    fn sh_command(body: &str) -> Command {
        let mut command = Command::new("/bin/sh");
        command.arg("-c").arg(body);
        command.env_clear();
        command.envs(allowlisted_child_env(
            "ETHEREUM_MAINNET_RPC_URL",
            "https://x/y",
        ));
        command
    }

    // The cap only means something if it also stops the read. A child that streams
    // without end must be killed, not drained: draining to EOF would hold the prover
    // here forever, which is exactly the hang the cap exists to prevent. Driven
    // through the real supervisor, so a regression fails here rather than in a
    // hand-rolled mirror of it that cannot drift with the production path.
    #[test]
    fn test_endless_toolkit_output_is_killed_not_drained() {
        let mut command = sh_command("while :; do printf 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'; done");
        let started = Instant::now();
        // A deadline far past what this needs: the size cap, not the clock, must be
        // what stops an endless child.
        let err = supervise_child(&mut command, Duration::from_secs(120), "https://x/y")
            .expect_err("an endless child must be refused");

        assert!(err.contains("too large"), "expected a size refusal: {err}");
        assert!(
            started.elapsed() < Duration::from_secs(60),
            "the cap must stop this well before the deadline, took {:?}",
            started.elapsed()
        );
    }

    // A child that overshoots the cap and then exits on its own never gets killed,
    // so the size refusal has to come from the flag rather than from the kill path.
    // Otherwise its truncated stdout reaches the parser and the operator gets an
    // unhelpful decode error in place of a precise size refusal.
    #[test]
    fn test_oversized_output_then_clean_exit_still_reports_size_refusal() {
        let body = format!(
            "dd if=/dev/zero bs=1024 count={} 2>/dev/null | tr '\\0' 'a'; exit 0",
            (MAX_TOOLKIT_STDOUT_BYTES / 1024) + 64
        );
        let mut command = sh_command(&body);
        let err = supervise_child(&mut command, Duration::from_secs(120), "https://x/y")
            .expect_err("an oversized bundle must be refused even on a clean exit");

        assert!(
            err.contains("too large"),
            "expected a size refusal, not a parse error: {err}"
        );
    }

    // The oversized-and-alive shape. A child that overshoots the cap and then closes
    // both pipes but keeps running fills both reader slots in one tick, so a loop
    // that checked the readers before the size flag would leave without killing,
    // skip the phase that bounds the child, and block on the reap for as long as the
    // child chose to live. The refusal string alone does not catch it: the wrong
    // implementation still returns "too large", just arbitrarily late. Assert the
    // clock, not the message.
    #[cfg(unix)]
    #[test]
    fn test_oversized_child_that_closes_pipes_and_lives_is_still_bounded() {
        let body = format!(
            "dd if=/dev/zero bs=1024 count={} 2>/dev/null | tr '\\0' 'a'; exec 1>&- 2>&-; sleep 60",
            (MAX_TOOLKIT_STDOUT_BYTES / 1024) + 64
        );
        let mut command = sh_command(&body);
        let started = Instant::now();
        let err = supervise_child(&mut command, Duration::from_secs(2), "https://x/y")
            .expect_err("an oversized bundle must be refused");
        let elapsed = started.elapsed();

        assert!(err.contains("too large"), "expected a size refusal: {err}");
        assert!(
            elapsed < Duration::from_secs(20),
            "the child, not the supervisor, decided when this returned: {elapsed:?}"
        );
    }

    #[test]
    fn test_well_behaved_child_completes_under_the_deadline() {
        let mut command = sh_command("printf 'hello'; exit 0");
        let outcome = supervise_child(&mut command, Duration::from_secs(30), "https://x/y")
            .expect("a well-behaved child must succeed");

        assert_eq!(outcome.stdout, b"hello");
        assert!(outcome.status.success());
        assert!(outcome.stdout_read.is_ok());
    }

    // A child that produces nothing and sleeps must be cut at the deadline rather
    // than at its own leisure.
    #[test]
    fn test_hanging_child_is_killed_at_the_deadline() {
        let mut command = sh_command("sleep 60");
        let started = Instant::now();
        let err = supervise_child(&mut command, Duration::from_millis(300), "https://x/y")
            .expect_err("a hanging child must time out");
        let elapsed = started.elapsed();

        assert!(err.contains("timed out"), "expected a timeout: {err}");
        assert!(
            elapsed < Duration::from_secs(10),
            "must return near the deadline, not near the sleep, took {elapsed:?}"
        );
    }

    // The grandchild pair. Both variants exercise different branches, and a single
    // combined test gives false assurance on one of them: with the child exiting,
    // a direct-child kill (or no kill at all) would pass a deadline-based assertion
    // because the deadline is never reached.

    // Variant A: a long-lived grandchild holds stdout while the child hangs. This is
    // the variant that discriminates. The deadline fires, and only a GROUP kill
    // releases the grandchild's write end, so the readers hit EOF at once and the
    // call returns at ~the deadline. A direct-child kill leaves them blocked on the
    // grandchild and the call instead returns at deadline + READER_GRACE, which the
    // bound below rejects. Keep that bound well under READER_GRACE or this test
    // silently stops testing anything.
    #[cfg(unix)]
    #[test]
    fn test_grandchild_holding_stdout_while_child_hangs_is_killed_at_the_deadline() {
        let mut command = sh_command("sleep 30 & printf 'partial'; sleep 60");
        let started = Instant::now();
        let err = supervise_child(&mut command, Duration::from_millis(300), "https://x/y")
            .expect_err("a hanging child must time out");
        let elapsed = started.elapsed();

        assert!(err.contains("timed out"), "expected a timeout: {err}");
        assert!(
            elapsed < Duration::from_secs(2),
            "the group kill must release the grandchild's pipe immediately; \
             taking ~READER_GRACE means only the direct child was killed. took {elapsed:?}"
        );
    }

    // Variant B: the child exits promptly while a grandchild keeps stdout open for a
    // while. Nothing is killed here and nothing should be: this pins the no-regression
    // property, since today's read-to-EOF completes such a run correctly (just
    // slowly). A supervisor that broke out on the child's exit would strand the
    // bundle bytes and fail the run.
    #[cfg(unix)]
    #[test]
    fn test_lingering_grandchild_after_child_exits_still_completes() {
        let mut command = sh_command("sleep 2 & printf 'done'; exit 0");
        let started = Instant::now();
        let outcome = supervise_child(&mut command, Duration::from_secs(60), "https://x/y")
            .expect("the child exited cleanly, so this must not be an error");
        let elapsed = started.elapsed();

        assert_eq!(outcome.stdout, b"done", "the child's bytes must survive");
        assert!(
            elapsed < Duration::from_secs(30),
            "supervisor stalled on the grandchild's pipe, took {elapsed:?}"
        );
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
