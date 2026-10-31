"""
Cryptographic Audit Attestation (Proof of Erasure)
HackerRank Orchestrate - Ghost Data Still Exists

This module provides cryptographic integrity attestation for deletion audit results.
It canonicalizes deletion case decisions and remediation/verification steps, computes
deterministic SHA-256 leaf hashes, and constructs a verifiable Merkle Tree.

Important Note:
A Merkle root cryptographically proves the integrity, non-repudiation, and immutability
of the audit trail relative to a trusted attestation point. It verifies that the audit
records and citations have not been altered or tampered with since attestation, but does
not physically prove bit-level erasure on external hardware storage media.
"""

from __future__ import annotations

import argparse
import csv
from datetime import datetime, timezone
import hashlib
import json
import os
import sys
from typing import Any, Dict, List, Optional, Tuple


def canonicalize_step(step: Dict[str, Any]) -> Dict[str, Any]:
    """Produces a canonical dictionary representation of an audit step."""
    return {
        "evidence_id": str(step.get("evidence_id", "")),
        "operation": str(step.get("operation", "")),
        "phase": str(step.get("phase", "")),
        "resource_id": str(step.get("resource_id", "")),
        "state": str(step.get("state", "")),
        "step_no": int(step.get("step_no", 0)),
        "system_id": str(step.get("system_id", "")),
    }


def canonicalize_case(case_id: str, deletion_status: str, steps: List[Dict[str, Any]]) -> bytes:
    """Serializes a case decision and its evidence trail into canonical JSON bytes."""
    canonical_dict = {
        "case_id": str(case_id).strip(),
        "deletion_status": str(deletion_status).strip(),
        "steps": [canonicalize_step(s) for s in sorted(steps, key=lambda x: int(x.get("step_no", 0)))],
    }
    return json.dumps(canonical_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")


def hash_leaf(data: bytes) -> str:
    """Computes SHA-256 digest of canonical data bytes."""
    return hashlib.sha256(data).hexdigest()


class MerkleTree:
    """
    Standard binary Merkle Tree with deterministic odd-leaf handling.
    
    If the number of nodes at any tree level is odd, the last node is duplicated
    to form a complete pair. Empty input yields the SHA-256 digest of the empty string.
    """

    EMPTY_ROOT = hashlib.sha256(b"").hexdigest()

    def __init__(self, leaves: Optional[List[str]] = None) -> None:
        self.leaves: List[str] = list(leaves) if leaves else []
        self.layers: List[List[str]] = []
        self._build_tree()

    def _build_tree(self) -> None:
        if not self.leaves:
            self.root = self.EMPTY_ROOT
            self.layers = []
            return

        current = list(self.leaves)
        self.layers.append(list(current))

        while len(current) > 1:
            # Deterministic odd leaf handling: duplicate last node
            if len(current) % 2 == 1:
                current.append(current[-1])

            next_layer: List[str] = []
            for i in range(0, len(current), 2):
                combined = current[i] + current[i + 1]
                parent = hashlib.sha256(combined.encode("utf-8")).hexdigest()
                next_layer.append(parent)

            self.layers.append(next_layer)
            current = next_layer

        self.root = current[0] if current else self.EMPTY_ROOT

    def get_proof(self, index: int) -> List[Dict[str, str]]:
        """
        Generates an audit proof path for the leaf at the given index.
        Each proof step contains 'position' ('left' or 'right') and 'hash'.
        """
        if index < 0 or index >= len(self.leaves):
            raise IndexError(f"Leaf index {index} out of range [0, {len(self.leaves)})")

        proof: List[Dict[str, str]] = []
        curr_idx = index

        for layer_idx in range(len(self.layers) - 1):
            layer = self.layers[layer_idx]
            # Account for duplicated odd leaf in layer
            working_layer = list(layer)
            if len(working_layer) % 2 == 1:
                working_layer.append(working_layer[-1])

            if curr_idx % 2 == 0:
                sibling_idx = curr_idx + 1
                position = "right"
            else:
                sibling_idx = curr_idx - 1
                position = "left"

            sibling_hash = working_layer[sibling_idx]
            proof.append({"position": position, "hash": sibling_hash})
            curr_idx = curr_idx // 2

        return proof

    @staticmethod
    def verify_proof(leaf_hash: str, proof: List[Dict[str, str]], expected_root: str) -> bool:
        """Verifies whether a leaf hash and audit proof reconstruct the expected Merkle root."""
        current = leaf_hash
        for step in proof:
            pos = step["position"]
            sibling = step["hash"]
            if pos == "left":
                combined = sibling + current
            elif pos == "right":
                combined = current + sibling
            else:
                return False
            current = hashlib.sha256(combined.encode("utf-8")).hexdigest()
        return current == expected_root


def generate_audit_attestation(output_csv_path: str) -> Dict[str, Any]:
    """
    Parses output.csv, canonicalizes every case, computes SHA-256 leaf hashes,
    builds the Merkle tree, and produces a complete audit attestation dictionary.
    """
    if not os.path.exists(output_csv_path):
        raise FileNotFoundError(f"output.csv not found at: {output_csv_path}")

    cases_data: List[Tuple[str, str, List[Dict[str, Any]]]] = []
    with open(output_csv_path, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            cid = row["case_id"]
            st = row["deletion_status"]
            steps_raw = row.get("steps_json", "[]")
            try:
                steps = json.loads(steps_raw)
            except Exception:
                steps = []
            cases_data.append((cid, st, steps))

    # Sort cases deterministically by integer id if formatted case_XX
    def parse_cid(item: Tuple[str, str, List[Dict[str, Any]]]) -> int:
        parts = item[0].split("_")
        if len(parts) > 1 and parts[1].isdigit():
            return int(parts[1])
        return 0

    cases_data.sort(key=parse_cid)

    leaf_hashes: List[str] = []
    case_entries: Dict[str, Dict[str, Any]] = {}

    for cid, st, steps in cases_data:
        canon_bytes = canonicalize_case(cid, st, steps)
        l_hash = hash_leaf(canon_bytes)
        leaf_hashes.append(l_hash)
        case_entries[cid] = {
            "case_id": cid,
            "deletion_status": st,
            "step_count": len(steps),
            "leaf_hash": l_hash,
            "proof": [],  # Will be populated below
        }

    tree = MerkleTree(leaf_hashes)

    # Attach Merkle proofs to individual cases
    for idx, (cid, _, _) in enumerate(cases_data):
        proof = tree.get_proof(idx)
        case_entries[cid]["proof"] = proof

    attestation: Dict[str, Any] = {
        "attestation_version": "1.0.0",
        "algorithm": "SHA-256",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "odd_leaf_policy": "duplicate_last",
        "empty_root": MerkleTree.EMPTY_ROOT,
        "total_cases": len(cases_data),
        "merkle_root": tree.root,
        "verification_metadata": {
            "canonicalization": "JSON sorted keys, compact separators (',', ':')",
            "hasher": "SHA-256 (NIST FIPS 180-4)",
            "verification_procedure": (
                "Compute hash_leaf(canonicalize_case(case_id, status, steps)). "
                "Traverse sibling hashes in 'proof'. Recomputed root must match 'merkle_root'."
            ),
            "integrity_scope": "Cryptographic integrity of audit attestation relative to root; not physical disk deletion.",
        },
        "cases": case_entries,
    }

    return attestation


def verify_attestation(attestation: Dict[str, Any], output_csv_path: str) -> Tuple[bool, List[str]]:
    """
    Verifies the integrity of an attestation against an output.csv file.
    Returns (is_valid, errors_list).
    """
    errors: List[str] = []
    expected_root = attestation.get("merkle_root", "")
    cases_dict = attestation.get("cases", {})

    if not os.path.exists(output_csv_path):
        return False, [f"Target file does not exist: {output_csv_path}"]

    with open(output_csv_path, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        found_cases = 0
        for row in reader:
            found_cases += 1
            cid = row["case_id"]
            st = row["deletion_status"]
            steps_raw = row.get("steps_json", "[]")
            try:
                steps = json.loads(steps_raw)
            except Exception as e:
                errors.append(f"Case {cid}: invalid JSON in steps: {e}")
                continue

            if cid not in cases_dict:
                errors.append(f"Case {cid} present in CSV but absent from attestation")
                continue

            att_case = cases_dict[cid]
            expected_leaf = att_case["leaf_hash"]
            actual_leaf = hash_leaf(canonicalize_case(cid, st, steps))

            if actual_leaf != expected_leaf:
                errors.append(
                    f"Case {cid}: Hash mismatch! Attested {expected_leaf[:12]}... but computed {actual_leaf[:12]}..."
                )
                continue

            # Verify Merkle proof up to root
            proof = att_case.get("proof", [])
            if not MerkleTree.verify_proof(actual_leaf, proof, expected_root):
                errors.append(f"Case {cid}: Merkle proof verification failed against root {expected_root[:12]}...")

    if found_cases != attestation.get("total_cases", 0):
        errors.append(
            f"Case count mismatch: CSV has {found_cases} cases, attestation has {attestation.get('total_cases', 0)}"
        )

    return len(errors) == 0, errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Cryptographic Proof of Erasure & Audit Attestation")
    parser.add_argument("--output-csv", default="output.csv", help="Path to output.csv")
    parser.add_argument("--attestation", default="audit_attestation.json", help="Path for audit_attestation.json")
    parser.add_argument("--verify", action="store_true", help="Verify existing attestation against output.csv")
    args = parser.parse_args()

    output_csv = args.output_csv
    if not os.path.exists(output_csv):
        code_out = os.path.join("code", "output.csv")
        if os.path.exists(code_out):
            output_csv = code_out

    if args.verify:
        if not os.path.exists(args.attestation):
            print(f"[ERROR] Attestation file not found: {args.attestation}")
            return 1
        with open(args.attestation, "r", encoding="utf-8") as f:
            att = json.load(f)
        is_ok, errs = verify_attestation(att, output_csv)
        if is_ok:
            print(f"[PASS] Attestation successfully verified against {output_csv}!")
            print(f"Merkle Root: {att.get('merkle_root')}")
            print(f"Verified Cases: {att.get('total_cases')}")
            return 0
        else:
            print(f"[FAIL] Attestation verification failed with {len(errs)} error(s):")
            for e in errs[:10]:
                print(f"  - {e}")
            return 1
    else:
        print(f"Generating cryptographic audit attestation from {output_csv}...")
        att = generate_audit_attestation(output_csv)
        with open(args.attestation, "w", encoding="utf-8") as f:
            json.dump(att, f, indent=2)
        print(f"[SUCCESS] Audit attestation written to {args.attestation}")
        print(f"Algorithm:   {att['algorithm']}")
        print(f"Total Cases: {att['total_cases']}")
        print(f"Merkle Root: {att['merkle_root']}")
        return 0


if __name__ == "__main__":
    sys.exit(main())
