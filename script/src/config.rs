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
