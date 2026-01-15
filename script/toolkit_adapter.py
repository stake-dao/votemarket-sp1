#!/usr/bin/env python3
"""
Run the VoteMarket proof toolkit for a host input JSON file.

The host input JSON follows the schema in votemarket-sp1/SPEC.md. This adapter
generates gauge and user proofs using the toolkit and emits a JSON bundle on stdout.
"""

from __future__ import annotations

import json
import sys
from typing import Dict, Iterable, List, Set, Tuple

from votemarket_toolkit.proofs import VoteMarketProofs
from votemarket_toolkit.utils import get_rounded_epoch


def _to_hex(value: bytes) -> str:
    return "0x" + value.hex()


def _collect_unique(values: Iterable[str]) -> List[str]:
    seen: Set[str] = set()
    ordered: List[str] = []
    for value in values:
        lower = value.lower()
        if lower in seen:
            continue
        seen.add(lower)
        ordered.append(value)
    return ordered


def _load_input(path: str) -> Dict:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: toolkit_adapter.py <host_input.json>", file=sys.stderr)
        return 1

    host_input = _load_input(sys.argv[1])
    chain_id = host_input["chain_id"]
    protocol = host_input.get("protocol", "curve")
    protocol = protocol.lower()
    block_number = host_input["block_number"]
    epoch = host_input.get("epoch")
    if epoch is None:
        raise ValueError("input JSON must include epoch")

    epoch = get_rounded_epoch(epoch)

    requests = host_input.get("requests", [])
    gauges_for_point: List[str] = []
    users_for_account: List[Tuple[str, str]] = []

    for request in requests:
        kind = request.get("type")
        gauge = request.get("gauge")
        account = request.get("account")
        if kind == "point_data" and gauge:
            gauges_for_point.append(gauge)
        elif kind == "account_data" and gauge and account:
            users_for_account.append((account, gauge))

    gauges_for_point = _collect_unique(gauges_for_point)
    users_for_account = [
        pair
        for pair in users_for_account
        if pair[0] and pair[1]
    ]

    toolkit = VoteMarketProofs(chain_id=chain_id)

    gauge_proofs = []
    for gauge in gauges_for_point:
        result = toolkit.get_gauge_proof(
            protocol=protocol,
            gauge_address=gauge,
            current_epoch=epoch,
            block_number=block_number,
        )
        gauge_proof = result.unwrap()
        gauge_proofs.append(
            {
                "gauge": gauge,
                "gauge_controller_proof": _to_hex(
                    gauge_proof["gauge_controller_proof"]
                ),
                "point_data_proof": _to_hex(gauge_proof["point_data_proof"]),
            }
        )

    user_proofs = []
    unique_users = {(account.lower(), gauge.lower()): (account, gauge) for account, gauge in users_for_account}
    for account, gauge in unique_users.values():
        result = toolkit.get_user_proof(
            protocol=protocol,
            gauge_address=gauge,
            user=account,
            block_number=block_number,
        )
        user_proof = result.unwrap()
        user_proofs.append(
            {
                "account": account,
                "gauge": gauge,
                "account_proof": _to_hex(user_proof["account_proof"]),
                "storage_proof": _to_hex(user_proof["storage_proof"]),
            }
        )

    bundle = {
        "protocol": protocol,
        "chain_id": chain_id,
        "block_number": block_number,
        "epoch": epoch,
        "gauge_proofs": gauge_proofs,
        "user_proofs": user_proofs,
    }

    print(json.dumps(bundle))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
