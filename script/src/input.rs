//! Input building from RPC or toolkit proofs.

use alloy_primitives::{Address, B256, U256};
use shared::{AccountRequest, Input, PointRequest};
use std::collections::HashMap;

use crate::helpers::{
    decode_proof_nodes, decode_rlp_node_list, decode_rlp_proof_list, ONE_WEEK_SECONDS,
};
use crate::protocol::{gauge_time_slot, user_vote_slots, Protocol, SlotRequest};
use crate::rpc::ProofResponse;
use crate::toolkit::ToolkitProofBundle;
use crate::types::{HostInput, RequestKind, RequestSlots};

///////////////////////////////////////////////
// INGESTION LIMITS
///////////////////////////////////////////////

/// Per-proof node-count ceiling. A mainnet account or storage proof is ~8-15 nodes
/// (trie depth), so this leaves an order of magnitude of headroom.
pub const MAX_PROOF_NODES: usize = 256;

/// Per-proof byte ceiling. A real proof is a few KB.
pub const MAX_PROOF_BYTES: usize = 256 * 1024;

/// Aggregate ceiling across every proof in one `Input`, enforced before the input
/// is handed to the prover.
pub const MAX_INPUT_BYTES: usize = 8 * 1024 * 1024;

///////////////////////////////////////////////
// VALIDATION
///////////////////////////////////////////////

/// Reject a gauge controller that is not the protocol's canonical one.
///
/// Defense in depth: `ZKVerifier._requireCanonicalController` already rejects a
/// non-canonical controller on-chain (`BAD_CONTROLLER`). Failing here too means a
/// mislabelled request dies before a proof is paid for, rather than at submission.
fn check_canonical_controller(protocol: Protocol, gauge_controller: Address) -> Result<(), String> {
    let canonical = protocol
        .gauge_controller()
        .ok_or_else(|| format!("no canonical gauge controller known for {protocol:?}"))?;
    if gauge_controller != canonical {
        return Err(format!(
            "uncanonical gauge_controller for {protocol:?}: got {gauge_controller}, expected {canonical}"
        ));
    }
    Ok(())
}

/// Measure one proof against the per-proof limits, returning its byte length.
fn check_proof_bounds(label: &str, proof: &[Vec<u8>]) -> Result<usize, String> {
    if proof.len() > MAX_PROOF_NODES {
        return Err(format!(
            "{label} proof has {} nodes, over the {MAX_PROOF_NODES} node cap",
            proof.len()
        ));
    }
    let bytes = proof.iter().try_fold(0usize, |acc, node| {
        acc.checked_add(node.len())
            .ok_or_else(|| format!("{label} proof byte count overflowed"))
    })?;
    if bytes > MAX_PROOF_BYTES {
        return Err(format!(
            "{label} proof is {bytes} bytes, over the {MAX_PROOF_BYTES} byte cap"
        ));
    }
    Ok(bytes)
}

/// Enforce the per-proof and aggregate ceilings across a whole `Input`.
///
/// Called at the end of both builders and again before the input is written to the
/// prover, so no construction path can skip it.
pub fn enforce_input_bounds(input: &Input) -> Result<(), String> {
    let mut total: usize = 0;
    let add = |label: &str, proof: &[Vec<u8>], total: &mut usize| -> Result<(), String> {
        let bytes = check_proof_bounds(label, proof)?;
        *total = total
            .checked_add(bytes)
            .ok_or_else(|| "input byte count overflowed".to_string())?;
        if *total > MAX_INPUT_BYTES {
            return Err(format!(
                "input is over the {MAX_INPUT_BYTES} byte aggregate cap"
            ));
        }
        Ok(())
    };

    for request in &input.point_requests {
        add("point account", &request.account_proof, &mut total)?;
        add("point bias", &request.bias_proof, &mut total)?;
    }
    for request in &input.account_requests {
        add("account", &request.account_proof, &mut total)?;
        add("account slope", &request.slope_proof, &mut total)?;
        add("account end", &request.end_proof, &mut total)?;
        if let Some(proof) = &request.last_vote_proof {
            add("account last_vote", proof, &mut total)?;
        }
    }
    Ok(())
}

///////////////////////////////////////////////
// REQUEST EXPANSION
///////////////////////////////////////////////

/// Expand host input requests into slot requests with computed storage positions.
pub fn expand_requests(input: &HostInput, epoch: u64) -> Result<Vec<RequestSlots>, String> {
    // Every epoch this system reasons about is a week boundary: the host derives it
    // by flooring the block timestamp to ONE_WEEK_SECONDS, and the on-chain oracle
    // keys its data the same way. Only an explicit override can be unaligned, and an
    // unaligned epoch derives slots no consumer will ever read.
    if epoch % ONE_WEEK_SECONDS != 0 {
        return Err(format!(
            "epoch {epoch} is not aligned to a {ONE_WEEK_SECONDS}-second week boundary"
        ));
    }

    let mut expanded = Vec::new();

    for request in &input.requests {
        let gauge = request
            .gauge
            .ok_or_else(|| "request missing gauge".to_string())?;
        let account = request.account;
        let mut slots = Vec::new();

        match request.kind {
            RequestKind::PointData => {
                let slot = gauge_time_slot(
                    input.protocol,
                    gauge,
                    epoch,
                    input.slots.weight_mapping_slot,
                );
                slots.push(SlotRequest {
                    label: "weight_bias".to_string(),
                    slot,
                });
            }
            RequestKind::AccountData => {
                if account.is_none() {
                    return Err("account_data request missing account".to_string());
                }

                slots.extend(user_vote_slots(
                    input.protocol,
                    account.unwrap(),
                    gauge,
                    input.slots.last_vote_mapping_slot,
                    input.slots.user_slope_mapping_slot,
                ));
            }
        }

        expanded.push(RequestSlots {
            kind: request.kind,
            account,
            gauge,
            slots,
        });
    }

    Ok(expanded)
}

///////////////////////////////////////////////
// INPUT BUILDING FROM RPC
///////////////////////////////////////////////

/// Build the Input structure from RPC proofs.
pub fn build_input_from_rpc(
    state_root: B256,
    epoch: u64,
    protocol: Protocol,
    gauge_controller: Address,
    requests: &[RequestSlots],
    proof: ProofResponse,
) -> Result<Input, String> {
    check_canonical_controller(protocol, gauge_controller)?;
    let account_proof = decode_proof_nodes(&proof.account_proof)?;

    // Map slot hex to storage proof
    let mut slot_to_proof: HashMap<U256, Vec<Vec<u8>>> = HashMap::new();
    let mut slot_index = 0;
    for request in requests {
        for slot in &request.slots {
            if slot_index >= proof.storage_proof.len() {
                return Err("not enough storage proofs".to_string());
            }
            let storage_proof = decode_proof_nodes(&proof.storage_proof[slot_index].proof)?;
            slot_to_proof.insert(slot.slot, storage_proof);
            slot_index += 1;
        }
    }

    let mut point_requests = Vec::new();
    let mut account_requests = Vec::new();

    for request in requests {
        match request.kind {
            RequestKind::PointData => {
                // Point data has a single slot (bias)
                let bias_slot = request
                    .slots
                    .iter()
                    .find(|s| s.label == "weight_bias")
                    .ok_or("missing weight_bias slot")?;

                let bias_proof = slot_to_proof
                    .get(&bias_slot.slot)
                    .ok_or("missing bias proof")?
                    .clone();

                point_requests.push(PointRequest {
                    protocol_id: protocol.as_u8(),
                    gauge: request.gauge,
                    gauge_controller,
                    account_proof: account_proof.clone(),
                    bias_proof,
                });
            }
            RequestKind::AccountData => {
                let account = request.account.ok_or("missing account for account_data")?;

                // Find required slots (host-internal: used to locate the matching proof).
                let slope_slot = request
                    .slots
                    .iter()
                    .find(|s| s.label == "user_slope")
                    .ok_or("missing user_slope slot")?;

                // Prefer the explicit `user_end`; fall back to `user_bias` only for
                // protocols without `user_end` (Pendle). Must match the guest's
                // `derive_account_slots` selection.
                let end_slot = request
                    .slots
                    .iter()
                    .find(|s| s.label == "user_end")
                    .or_else(|| request.slots.iter().find(|s| s.label == "user_bias"))
                    .ok_or("missing user_end/user_bias slot")?;

                let last_vote_slot = request.slots.iter().find(|s| s.label == "last_vote");

                let slope_proof = slot_to_proof
                    .get(&slope_slot.slot)
                    .ok_or("missing slope proof")?
                    .clone();

                let end_proof = slot_to_proof
                    .get(&end_slot.slot)
                    .ok_or("missing end proof")?
                    .clone();

                let last_vote_proof = match last_vote_slot {
                    Some(slot) => Some(
                        slot_to_proof
                            .get(&slot.slot)
                            .ok_or("missing last_vote proof")?
                            .clone(),
                    ),
                    None => None,
                };

                account_requests.push(AccountRequest {
                    protocol_id: protocol.as_u8(),
                    account,
                    gauge: request.gauge,
                    gauge_controller,
                    account_proof: account_proof.clone(),
                    slope_proof,
                    end_proof,
                    last_vote_proof,
                });
            }
        }
    }

    let input = Input {
        state_root,
        epoch,
        point_requests,
        account_requests,
    };
    enforce_input_bounds(&input)?;
    Ok(input)
}

///////////////////////////////////////////////
// INPUT BUILDING FROM TOOLKIT
///////////////////////////////////////////////

/// Build the Input structure from toolkit proofs.
pub fn build_input_from_toolkit(
    state_root: B256,
    epoch: u64,
    protocol: Protocol,
    gauge_controller: Address,
    requests: &[RequestSlots],
    bundle: ToolkitProofBundle,
) -> Result<Input, String> {
    check_canonical_controller(protocol, gauge_controller)?;
    let mut gauge_proofs = HashMap::new();
    for proof in bundle.gauge_proofs {
        gauge_proofs.insert(proof.gauge, proof);
    }

    let mut user_proofs = HashMap::new();
    for proof in bundle.user_proofs {
        user_proofs.insert((proof.account, proof.gauge), proof);
    }

    // Get account proof from first available proof
    let mut account_proof_nodes: Option<Vec<Vec<u8>>> = None;
    if let Some(proof) = gauge_proofs.values().next() {
        account_proof_nodes = Some(decode_rlp_node_list(&proof.gauge_controller_proof)?);
    } else if let Some(proof) = user_proofs.values().next() {
        account_proof_nodes = Some(decode_rlp_node_list(&proof.account_proof)?);
    }
    let account_proof_nodes =
        account_proof_nodes.ok_or_else(|| "missing account proof".to_string())?;

    let mut point_requests = Vec::new();
    let mut account_requests = Vec::new();

    for request in requests {
        match request.kind {
            RequestKind::PointData => {
                let toolkit_proof = gauge_proofs
                    .get(&request.gauge)
                    .ok_or_else(|| format!("missing gauge proof for {}", request.gauge))?;

                let proofs = decode_rlp_proof_list(&toolkit_proof.point_data_proof)?;
                if proofs.is_empty() {
                    return Err("empty point_data_proof".to_string());
                }

                point_requests.push(PointRequest {
                    protocol_id: protocol.as_u8(),
                    gauge: request.gauge,
                    gauge_controller,
                    account_proof: account_proof_nodes.clone(),
                    bias_proof: proofs[0].clone(),
                });
            }
            RequestKind::AccountData => {
                let account = request.account.ok_or("missing account for account_data")?;
                let key = (account, request.gauge);

                let toolkit_proof = user_proofs
                    .get(&key)
                    .ok_or_else(|| format!("missing user proof for {key:?}"))?;

                let proofs = decode_rlp_proof_list(&toolkit_proof.storage_proof)?;

                // Find slot indices by label
                let slope_idx = request
                    .slots
                    .iter()
                    .position(|s| s.label == "user_slope")
                    .ok_or("missing user_slope slot")?;

                // Prefer the explicit `user_end`; fall back to `user_bias` only for
                // protocols without `user_end` (Pendle). Must match the guest.
                let end_idx = request
                    .slots
                    .iter()
                    .position(|s| s.label == "user_end")
                    .or_else(|| request.slots.iter().position(|s| s.label == "user_bias"))
                    .ok_or("missing user_end/user_bias slot")?;

                let last_vote_idx = request.slots.iter().position(|s| s.label == "last_vote");

                if proofs.len() < request.slots.len() {
                    return Err(format!(
                        "not enough proofs: expected {}, got {}",
                        request.slots.len(),
                        proofs.len()
                    ));
                }

                let last_vote_proof = last_vote_idx.map(|idx| proofs[idx].clone());

                account_requests.push(AccountRequest {
                    protocol_id: protocol.as_u8(),
                    account,
                    gauge: request.gauge,
                    gauge_controller,
                    account_proof: account_proof_nodes.clone(),
                    slope_proof: proofs[slope_idx].clone(),
                    end_proof: proofs[end_idx].clone(),
                    last_vote_proof,
                });
            }
        }
    }

    let input = Input {
        state_root,
        epoch,
        point_requests,
        account_requests,
    };
    enforce_input_bounds(&input)?;
    Ok(input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{Protocol, SlotConfig};
    use crate::types::{HostInput, RequestItem, RequestKind};
    use alloy_primitives::{address, U256};

    // Test fixtures
    const TEST_GAUGE: Address = address!("26f7786de3e6d9bd37fcf47be6f2bc455a21b74a");
    const TEST_ACCOUNT: Address = address!("fac2f11ba2577d5122dc1ec5301d35b16688251e");
    const TEST_EPOCH: u64 = 1730937600;

    fn make_test_host_input(protocol: Protocol, requests: Vec<RequestItem>) -> HostInput {
        let slots = protocol.toolkit_slots().unwrap_or(SlotConfig {
            weight_mapping_slot: U256::from(12),
            last_vote_mapping_slot: U256::from(11),
            user_slope_mapping_slot: U256::from(9),
        });
        HostInput {
            chain_id: 1,
            block_number: Some(21134723),
            epoch_override: Some(TEST_EPOCH),
            protocol,
            protocol_name: "curve".to_string(),
            gauge_controller: protocol
                .gauge_controller()
                .unwrap_or(address!("2F50D538606Fa9EDD2B11E2446BEb18C9D5846bB")),
            slots,
            requests,
        }
    }

    ///////////////////////////////////////////////
    // EXPAND REQUESTS TESTS
    ///////////////////////////////////////////////

    #[test]
    fn test_expand_requests_point_data() {
        let requests = vec![RequestItem {
            kind: RequestKind::PointData,
            account: None,
            gauge: Some(TEST_GAUGE),
        }];
        let input = make_test_host_input(Protocol::Curve, requests);
        let expanded = expand_requests(&input, TEST_EPOCH).unwrap();

        assert_eq!(expanded.len(), 1);
        assert!(matches!(expanded[0].kind, RequestKind::PointData));
        assert_eq!(expanded[0].gauge, TEST_GAUGE);
        assert!(expanded[0].account.is_none());
        // Point data should have a single weight_bias slot
        assert_eq!(expanded[0].slots.len(), 1);
        assert_eq!(expanded[0].slots[0].label, "weight_bias");
    }

    #[test]
    fn test_expand_requests_account_data_curve() {
        let requests = vec![RequestItem {
            kind: RequestKind::AccountData,
            account: Some(TEST_ACCOUNT),
            gauge: Some(TEST_GAUGE),
        }];
        let input = make_test_host_input(Protocol::Curve, requests);
        let expanded = expand_requests(&input, TEST_EPOCH).unwrap();

        assert_eq!(expanded.len(), 1);
        assert!(matches!(expanded[0].kind, RequestKind::AccountData));
        assert_eq!(expanded[0].account, Some(TEST_ACCOUNT));
        // Curve account data should have 3 slots: last_vote, user_slope, user_end
        assert_eq!(expanded[0].slots.len(), 3);
        assert!(expanded[0].slots.iter().any(|s| s.label == "last_vote"));
        assert!(expanded[0].slots.iter().any(|s| s.label == "user_slope"));
        assert!(expanded[0].slots.iter().any(|s| s.label == "user_end"));
    }

    #[test]
    fn test_expand_requests_account_data_pendle_no_last_vote() {
        let requests = vec![RequestItem {
            kind: RequestKind::AccountData,
            account: Some(TEST_ACCOUNT),
            gauge: Some(TEST_GAUGE),
        }];
        let input = make_test_host_input(Protocol::Pendle, requests);
        let expanded = expand_requests(&input, TEST_EPOCH).unwrap();

        // Pendle should NOT have last_vote slot
        assert!(!expanded[0].slots.iter().any(|s| s.label == "last_vote"));
        // Pendle should have user_slope and user_bias
        assert!(expanded[0].slots.iter().any(|s| s.label == "user_slope"));
        assert!(expanded[0].slots.iter().any(|s| s.label == "user_bias"));
    }

    #[test]
    fn test_expand_requests_missing_gauge_error() {
        let requests = vec![RequestItem {
            kind: RequestKind::PointData,
            account: None,
            gauge: None, // Missing gauge
        }];
        let input = make_test_host_input(Protocol::Curve, requests);
        let result = expand_requests(&input, TEST_EPOCH);

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing gauge"));
    }

    #[test]
    fn test_expand_requests_missing_account_error() {
        let requests = vec![RequestItem {
            kind: RequestKind::AccountData,
            account: None, // Missing account for account_data
            gauge: Some(TEST_GAUGE),
        }];
        let input = make_test_host_input(Protocol::Curve, requests);
        let result = expand_requests(&input, TEST_EPOCH);

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing account"));
    }

    #[test]
    fn test_expand_requests_multiple_requests() {
        let requests = vec![
            RequestItem {
                kind: RequestKind::PointData,
                account: None,
                gauge: Some(TEST_GAUGE),
            },
            RequestItem {
                kind: RequestKind::AccountData,
                account: Some(TEST_ACCOUNT),
                gauge: Some(TEST_GAUGE),
            },
        ];
        let input = make_test_host_input(Protocol::Curve, requests);
        let expanded = expand_requests(&input, TEST_EPOCH).unwrap();

        assert_eq!(expanded.len(), 2);
        assert!(matches!(expanded[0].kind, RequestKind::PointData));
        assert!(matches!(expanded[1].kind, RequestKind::AccountData));
    }

    #[test]
    fn test_expand_requests_empty() {
        let input = make_test_host_input(Protocol::Curve, vec![]);
        let expanded = expand_requests(&input, TEST_EPOCH).unwrap();
        assert!(expanded.is_empty());
    }

    #[test]
    fn test_expand_requests_yb_has_four_slots() {
        let requests = vec![RequestItem {
            kind: RequestKind::AccountData,
            account: Some(TEST_ACCOUNT),
            gauge: Some(TEST_GAUGE),
        }];
        let input = make_test_host_input(Protocol::Yb, requests);
        let expanded = expand_requests(&input, TEST_EPOCH).unwrap();

        // Yb should have 4 slots: last_vote, user_slope, user_bias, user_end
        assert_eq!(expanded[0].slots.len(), 4);
    }

    ///////////////////////////////////////////////
    // EPOCH ALIGNMENT TESTS
    ///////////////////////////////////////////////

    #[test]
    fn test_expand_requests_rejects_unaligned_epoch() {
        let requests = vec![RequestItem {
            kind: RequestKind::PointData,
            account: None,
            gauge: Some(TEST_GAUGE),
        }];
        let input = make_test_host_input(Protocol::Curve, requests);

        // One second past a week boundary is enough: the oracle keys on the boundary,
        // so this derives slots nothing on-chain will ever read.
        let err = expand_requests(&input, TEST_EPOCH + 1)
            .expect_err("an unaligned epoch must be refused");
        assert!(err.contains("not aligned"), "got: {err}");
    }

    #[test]
    fn test_expand_requests_accepts_week_boundary_epochs() {
        for offset in [0u64, 604800, 604800 * 52] {
            let requests = vec![RequestItem {
                kind: RequestKind::PointData,
                account: None,
                gauge: Some(TEST_GAUGE),
            }];
            let input = make_test_host_input(Protocol::Curve, requests);
            assert!(expand_requests(&input, TEST_EPOCH + offset).is_ok());
        }
    }

    ///////////////////////////////////////////////
    // CANONICAL CONTROLLER TESTS
    ///////////////////////////////////////////////

    #[test]
    fn test_check_canonical_controller_accepts_canonical() {
        for protocol in [
            Protocol::Curve,
            Protocol::Balancer,
            Protocol::Frax,
            Protocol::Fxn,
            Protocol::Yb,
            Protocol::Pendle,
        ] {
            let canonical = protocol.gauge_controller().unwrap();
            assert!(check_canonical_controller(protocol, canonical).is_ok());
        }
    }

    #[test]
    fn test_check_canonical_controller_rejects_attacker_address() {
        let err = check_canonical_controller(Protocol::Curve, Address::ZERO)
            .expect_err("the zero address is not Curve's controller");
        assert!(err.contains("uncanonical"), "got: {err}");

        // Another protocol's real controller is the more realistic mislabel.
        let err = check_canonical_controller(
            Protocol::Curve,
            Protocol::Balancer.gauge_controller().unwrap(),
        )
        .expect_err("a sibling protocol's controller must not pass as Curve's");
        assert!(err.contains("uncanonical"), "got: {err}");
    }

    #[test]
    fn test_build_input_from_rpc_rejects_uncanonical_controller() {
        let requests = vec![RequestItem {
            kind: RequestKind::PointData,
            account: None,
            gauge: Some(TEST_GAUGE),
        }];
        let input = make_test_host_input(Protocol::Curve, requests);
        let expanded = expand_requests(&input, TEST_EPOCH).unwrap();

        let result = build_input_from_rpc(
            B256::ZERO,
            TEST_EPOCH,
            Protocol::Curve,
            Address::repeat_byte(0x66),
            &expanded,
            ProofResponse {
                account_proof: vec![],
                storage_proof: vec![],
            },
        );
        let err = result.expect_err("an uncanonical controller must be refused");
        assert!(err.contains("uncanonical"), "got: {err}");
    }

    ///////////////////////////////////////////////
    // INGESTION BOUND TESTS
    ///////////////////////////////////////////////

    fn point_request_with_proof(bias_proof: Vec<Vec<u8>>) -> Input {
        Input {
            state_root: B256::ZERO,
            epoch: TEST_EPOCH,
            point_requests: vec![PointRequest {
                protocol_id: Protocol::Curve.as_u8(),
                gauge: TEST_GAUGE,
                gauge_controller: Protocol::Curve.gauge_controller().unwrap(),
                account_proof: vec![vec![0u8; 64]],
                bias_proof,
            }],
            account_requests: vec![],
        }
    }

    #[test]
    fn test_enforce_input_bounds_accepts_realistic_proof() {
        // A real mainnet proof is ~8-15 nodes of a few hundred bytes each.
        let realistic = vec![vec![0u8; 532]; 12];
        assert!(enforce_input_bounds(&point_request_with_proof(realistic)).is_ok());
    }

    #[test]
    fn test_enforce_input_bounds_rejects_too_many_nodes() {
        let too_many = vec![vec![0u8; 4]; MAX_PROOF_NODES + 1];
        let err = enforce_input_bounds(&point_request_with_proof(too_many))
            .expect_err("node count over the cap must be refused");
        assert!(err.contains("node cap"), "got: {err}");
    }

    #[test]
    fn test_enforce_input_bounds_rejects_oversized_proof_bytes() {
        // Few nodes, but each enormous: the node count alone would not catch this.
        let fat = vec![vec![0u8; MAX_PROOF_BYTES / 2]; 3];
        let err = enforce_input_bounds(&point_request_with_proof(fat))
            .expect_err("byte size over the cap must be refused");
        assert!(err.contains("byte cap"), "got: {err}");
    }

    #[test]
    fn test_enforce_input_bounds_rejects_oversized_aggregate() {
        // Each proof is individually legal; only the running total trips the cap.
        let per_proof = vec![vec![0u8; MAX_PROOF_BYTES]; 1];
        let count = (MAX_INPUT_BYTES / MAX_PROOF_BYTES) + 2;
        let input = Input {
            state_root: B256::ZERO,
            epoch: TEST_EPOCH,
            point_requests: (0..count)
                .map(|_| PointRequest {
                    protocol_id: Protocol::Curve.as_u8(),
                    gauge: TEST_GAUGE,
                    gauge_controller: Protocol::Curve.gauge_controller().unwrap(),
                    account_proof: vec![],
                    bias_proof: per_proof.clone(),
                })
                .collect(),
            account_requests: vec![],
        };
        let err = enforce_input_bounds(&input).expect_err("aggregate over the cap must be refused");
        assert!(err.contains("aggregate cap"), "got: {err}");
    }

    #[test]
    fn test_enforce_input_bounds_covers_account_request_proofs() {
        let input = Input {
            state_root: B256::ZERO,
            epoch: TEST_EPOCH,
            point_requests: vec![],
            account_requests: vec![AccountRequest {
                protocol_id: Protocol::Curve.as_u8(),
                account: TEST_ACCOUNT,
                gauge: TEST_GAUGE,
                gauge_controller: Protocol::Curve.gauge_controller().unwrap(),
                account_proof: vec![],
                slope_proof: vec![],
                end_proof: vec![],
                // The optional proof is bounded too, not skipped with the `None` arm.
                last_vote_proof: Some(vec![vec![0u8; 4]; MAX_PROOF_NODES + 1]),
            }],
        };
        let err = enforce_input_bounds(&input).expect_err("last_vote proof must be bounded");
        assert!(err.contains("last_vote"), "got: {err}");
    }

    #[test]
    fn test_expand_requests_different_epochs_different_slots() {
        let requests1 = vec![RequestItem {
            kind: RequestKind::PointData,
            account: None,
            gauge: Some(TEST_GAUGE),
        }];
        let input1 = make_test_host_input(Protocol::Balancer, requests1);
        let expanded1 = expand_requests(&input1, TEST_EPOCH).unwrap();

        let requests2 = vec![RequestItem {
            kind: RequestKind::PointData,
            account: None,
            gauge: Some(TEST_GAUGE),
        }];
        let input2 = make_test_host_input(Protocol::Balancer, requests2);
        let expanded2 = expand_requests(&input2, TEST_EPOCH + 604800).unwrap();

        // Different epochs should produce different slots for protocols that use epoch
        assert_ne!(expanded1[0].slots[0].slot, expanded2[0].slots[0].slot);
    }
}
