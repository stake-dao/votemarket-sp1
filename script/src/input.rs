//! Input building from RPC or toolkit proofs.

use alloy_primitives::{Address, B256, U256};
use shared::{AccountRequest, Input, PointRequest};
use std::collections::HashMap;

use crate::helpers::{decode_proof_nodes, decode_rlp_node_list, decode_rlp_proof_list};
use crate::protocol::{gauge_time_slot, user_vote_slots, SlotRequest};
use crate::rpc::ProofResponse;
use crate::toolkit::ToolkitProofBundle;
use crate::types::{HostInput, RequestKind, RequestSlots};

///////////////////////////////////////////////
// REQUEST EXPANSION
///////////////////////////////////////////////

/// Expand host input requests into slot requests with computed storage positions.
pub fn expand_requests(input: &HostInput, epoch: u64) -> Result<Vec<RequestSlots>, String> {
    let mut expanded = Vec::new();

    for request in &input.requests {
        let gauge = request
            .gauge
            .ok_or_else(|| "request missing gauge".to_string())?;
        let account = request.account;
        let mut slots = Vec::new();

        match request.kind {
            RequestKind::PointData => {
                let slot = gauge_time_slot(input.protocol, gauge, epoch, input.slots.weight_mapping_slot);
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
    gauge_controller: Address,
    requests: &[RequestSlots],
    proof: ProofResponse,
) -> Result<Input, String> {
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
                    gauge: request.gauge,
                    gauge_controller,
                    account_proof: account_proof.clone(),
                    bias_proof,
                    bias_slot: bias_slot.slot,
                });
            }
            RequestKind::AccountData => {
                let account = request.account.ok_or("missing account for account_data")?;

                // Find required slots
                let slope_slot = request
                    .slots
                    .iter()
                    .find(|s| s.label == "user_slope")
                    .ok_or("missing user_slope slot")?;

                let end_slot = request
                    .slots
                    .iter()
                    .find(|s| s.label == "user_end" || s.label == "user_bias")
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

                let (last_vote_proof, last_vote_slot_val) = match last_vote_slot {
                    Some(slot) => {
                        let proof = slot_to_proof
                            .get(&slot.slot)
                            .ok_or("missing last_vote proof")?
                            .clone();
                        (Some(proof), Some(slot.slot))
                    }
                    None => (None, None),
                };

                account_requests.push(AccountRequest {
                    account,
                    gauge: request.gauge,
                    gauge_controller,
                    account_proof: account_proof.clone(),
                    slope_proof,
                    end_proof,
                    last_vote_proof,
                    slope_slot: slope_slot.slot,
                    end_slot: end_slot.slot,
                    last_vote_slot: last_vote_slot_val,
                });
            }
        }
    }

    Ok(Input {
        state_root,
        epoch,
        point_requests,
        account_requests,
    })
}

///////////////////////////////////////////////
// INPUT BUILDING FROM TOOLKIT
///////////////////////////////////////////////

/// Build the Input structure from toolkit proofs.
pub fn build_input_from_toolkit(
    state_root: B256,
    epoch: u64,
    gauge_controller: Address,
    requests: &[RequestSlots],
    bundle: ToolkitProofBundle,
) -> Result<Input, String> {
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

                let bias_slot = request
                    .slots
                    .iter()
                    .find(|s| s.label == "weight_bias")
                    .ok_or("missing weight_bias slot")?;

                point_requests.push(PointRequest {
                    gauge: request.gauge,
                    gauge_controller,
                    account_proof: account_proof_nodes.clone(),
                    bias_proof: proofs[0].clone(),
                    bias_slot: bias_slot.slot,
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

                let end_idx = request
                    .slots
                    .iter()
                    .position(|s| s.label == "user_end" || s.label == "user_bias")
                    .ok_or("missing user_end/user_bias slot")?;

                let last_vote_idx = request.slots.iter().position(|s| s.label == "last_vote");

                if proofs.len() < request.slots.len() {
                    return Err(format!(
                        "not enough proofs: expected {}, got {}",
                        request.slots.len(),
                        proofs.len()
                    ));
                }

                let slope_slot = &request.slots[slope_idx];
                let end_slot = &request.slots[end_idx];

                let (last_vote_proof, last_vote_slot_val) = match last_vote_idx {
                    Some(idx) => (Some(proofs[idx].clone()), Some(request.slots[idx].slot)),
                    None => (None, None),
                };

                account_requests.push(AccountRequest {
                    account,
                    gauge: request.gauge,
                    gauge_controller,
                    account_proof: account_proof_nodes.clone(),
                    slope_proof: proofs[slope_idx].clone(),
                    end_proof: proofs[end_idx].clone(),
                    last_vote_proof,
                    slope_slot: slope_slot.slot,
                    end_slot: end_slot.slot,
                    last_vote_slot: last_vote_slot_val,
                });
            }
        }
    }

    Ok(Input {
        state_root,
        epoch,
        point_requests,
        account_requests,
    })
}
