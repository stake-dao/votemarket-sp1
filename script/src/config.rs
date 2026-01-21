//! Configuration enums for run mode, proof kind, and proof source.

use std::env;

/// Determines whether to execute (mock) or generate a real proof.
#[derive(Debug, Clone, Copy)]
pub enum RunMode {
    Execute,
    Prove,
}

impl RunMode {
    pub fn from_env() -> Self {
        match env::var("RUN_MODE")
            .unwrap_or_else(|_| "execute".to_string())
            .to_lowercase()
            .as_str()
        {
            "prove" => Self::Prove,
            _ => Self::Execute,
        }
    }
}

/// The type of ZK proof to generate.
#[derive(Debug, Clone, Copy)]
pub enum ProofKind {
    /// Raw SP1 STARK proof; largest, fastest to generate, off-chain only.
    Core,
    /// Recursively compressed STARK; smaller, still off-chain.
    Compressed,
    /// Wrap in BN254 PLONK SNARK; EVM-verifiable, universal setup.
    Plonk,
    /// Wrap in BN254 Groth16 SNARK; smallest proof, cheapest on-chain.
    Groth16,
}

impl ProofKind {
    pub fn from_env() -> Self {
        match env::var("PROOF_KIND")
            .unwrap_or_else(|_| "core".to_string())
            .to_lowercase()
            .as_str()
        {
            "compressed" => Self::Compressed,
            "plonk" => Self::Plonk,
            "groth16" => Self::Groth16,
            _ => Self::Core,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ProofKind::Core => "core",
            ProofKind::Compressed => "compressed",
            ProofKind::Plonk => "plonk",
            ProofKind::Groth16 => "groth16",
        }
    }
}

/// Source for fetching Merkle proofs.
#[derive(Debug, Clone, Copy)]
pub enum ProofSource {
    /// Fetch proofs directly from Ethereum RPC.
    Rpc,
    /// Use the Python toolkit to generate proofs.
    Toolkit,
}

impl ProofSource {
    pub fn from_env() -> Self {
        match env::var("PROOF_SOURCE")
            .unwrap_or_else(|_| "toolkit".to_string())
            .to_lowercase()
            .as_str()
        {
            "rpc" => Self::Rpc,
            _ => Self::Toolkit,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Mutex to ensure env var tests don't interfere with each other
    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    ///////////////////////////////////////////////
    // PROOF KIND TESTS
    ///////////////////////////////////////////////

    #[test]
    fn test_proof_kind_as_str_core() {
        assert_eq!(ProofKind::Core.as_str(), "core");
    }

    #[test]
    fn test_proof_kind_as_str_compressed() {
        assert_eq!(ProofKind::Compressed.as_str(), "compressed");
    }

    #[test]
    fn test_proof_kind_as_str_plonk() {
        assert_eq!(ProofKind::Plonk.as_str(), "plonk");
    }

    #[test]
    fn test_proof_kind_as_str_groth16() {
        assert_eq!(ProofKind::Groth16.as_str(), "groth16");
    }

    #[test]
    fn test_proof_kind_from_env_core() {
        let _guard = ENV_MUTEX.lock().unwrap();
        env::set_var("PROOF_KIND", "core");
        let kind = ProofKind::from_env();
        env::remove_var("PROOF_KIND");
        assert!(matches!(kind, ProofKind::Core));
    }

    #[test]
    fn test_proof_kind_from_env_compressed() {
        let _guard = ENV_MUTEX.lock().unwrap();
        env::set_var("PROOF_KIND", "compressed");
        let kind = ProofKind::from_env();
        env::remove_var("PROOF_KIND");
        assert!(matches!(kind, ProofKind::Compressed));
    }

    #[test]
    fn test_proof_kind_from_env_plonk() {
        let _guard = ENV_MUTEX.lock().unwrap();
        env::set_var("PROOF_KIND", "plonk");
        let kind = ProofKind::from_env();
        env::remove_var("PROOF_KIND");
        assert!(matches!(kind, ProofKind::Plonk));
    }

    #[test]
    fn test_proof_kind_from_env_groth16() {
        let _guard = ENV_MUTEX.lock().unwrap();
        env::set_var("PROOF_KIND", "groth16");
        let kind = ProofKind::from_env();
        env::remove_var("PROOF_KIND");
        assert!(matches!(kind, ProofKind::Groth16));
    }

    #[test]
    fn test_proof_kind_from_env_default() {
        let _guard = ENV_MUTEX.lock().unwrap();
        env::remove_var("PROOF_KIND");
        let kind = ProofKind::from_env();
        assert!(matches!(kind, ProofKind::Core));
    }

    #[test]
    fn test_proof_kind_from_env_unknown_defaults_to_core() {
        let _guard = ENV_MUTEX.lock().unwrap();
        env::set_var("PROOF_KIND", "unknown");
        let kind = ProofKind::from_env();
        env::remove_var("PROOF_KIND");
        assert!(matches!(kind, ProofKind::Core));
    }

    #[test]
    fn test_proof_kind_from_env_case_insensitive() {
        let _guard = ENV_MUTEX.lock().unwrap();
        env::set_var("PROOF_KIND", "GROTH16");
        let kind = ProofKind::from_env();
        env::remove_var("PROOF_KIND");
        assert!(matches!(kind, ProofKind::Groth16));
    }

    ///////////////////////////////////////////////
    // RUN MODE TESTS
    ///////////////////////////////////////////////

    #[test]
    fn test_run_mode_from_env_execute() {
        let _guard = ENV_MUTEX.lock().unwrap();
        env::set_var("RUN_MODE", "execute");
        let mode = RunMode::from_env();
        env::remove_var("RUN_MODE");
        assert!(matches!(mode, RunMode::Execute));
    }

    #[test]
    fn test_run_mode_from_env_prove() {
        let _guard = ENV_MUTEX.lock().unwrap();
        env::set_var("RUN_MODE", "prove");
        let mode = RunMode::from_env();
        env::remove_var("RUN_MODE");
        assert!(matches!(mode, RunMode::Prove));
    }

    #[test]
    fn test_run_mode_from_env_uppercase() {
        let _guard = ENV_MUTEX.lock().unwrap();
        env::set_var("RUN_MODE", "PROVE");
        let mode = RunMode::from_env();
        env::remove_var("RUN_MODE");
        assert!(matches!(mode, RunMode::Prove));
    }

    #[test]
    fn test_run_mode_from_env_default() {
        let _guard = ENV_MUTEX.lock().unwrap();
        env::remove_var("RUN_MODE");
        let mode = RunMode::from_env();
        assert!(matches!(mode, RunMode::Execute));
    }

    #[test]
    fn test_run_mode_from_env_unknown_defaults_to_execute() {
        let _guard = ENV_MUTEX.lock().unwrap();
        env::set_var("RUN_MODE", "unknown");
        let mode = RunMode::from_env();
        env::remove_var("RUN_MODE");
        assert!(matches!(mode, RunMode::Execute));
    }

    ///////////////////////////////////////////////
    // PROOF SOURCE TESTS
    ///////////////////////////////////////////////

    #[test]
    fn test_proof_source_from_env_rpc() {
        let _guard = ENV_MUTEX.lock().unwrap();
        env::set_var("PROOF_SOURCE", "rpc");
        let source = ProofSource::from_env();
        env::remove_var("PROOF_SOURCE");
        assert!(matches!(source, ProofSource::Rpc));
    }

    #[test]
    fn test_proof_source_from_env_toolkit() {
        let _guard = ENV_MUTEX.lock().unwrap();
        env::set_var("PROOF_SOURCE", "toolkit");
        let source = ProofSource::from_env();
        env::remove_var("PROOF_SOURCE");
        assert!(matches!(source, ProofSource::Toolkit));
    }

    #[test]
    fn test_proof_source_from_env_default() {
        let _guard = ENV_MUTEX.lock().unwrap();
        env::remove_var("PROOF_SOURCE");
        let source = ProofSource::from_env();
        assert!(matches!(source, ProofSource::Toolkit));
    }

    #[test]
    fn test_proof_source_from_env_unknown_defaults_to_toolkit() {
        let _guard = ENV_MUTEX.lock().unwrap();
        env::set_var("PROOF_SOURCE", "unknown");
        let source = ProofSource::from_env();
        env::remove_var("PROOF_SOURCE");
        assert!(matches!(source, ProofSource::Toolkit));
    }

    #[test]
    fn test_proof_source_from_env_case_insensitive() {
        let _guard = ENV_MUTEX.lock().unwrap();
        env::set_var("PROOF_SOURCE", "RPC");
        let source = ProofSource::from_env();
        env::remove_var("PROOF_SOURCE");
        assert!(matches!(source, ProofSource::Rpc));
    }
}
