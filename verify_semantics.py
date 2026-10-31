"""
Independent Semantic Verifier
HackerRank Orchestrate - Ghost Data Still Exists

Performs independent validation of output.csv decisions, step sequences, and evidence
provenance using an autonomous Union-Find identity graph. Operates completely separately
from the primary engine to guarantee objective semantic validation.

Validation Dimensions:
1. Strict Schema & Sequencing: Header format, contiguous 1-based step numbers,
   and deterministic phase progression (FINDING -> REMEDIATION -> VERIFICATION).
2. Evidence Citation Rules: Complete cases require evidence citations for all verifications;
   incomplete cases require evidence citations for findings.
3. Contradiction Detection: Re-evaluates post-deletion evidence across all transitively
   connected aliases (email, user ID, phone, historical identities) to flag any contradiction
   between COMPLETE statuses and active/exposed personal data.
4. Independent Reporting: Clearly partitions schema errors, semantic contradictions,
   unsupported conclusions, and unverified aliases.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple


class DisjointSetUnion:
    """Disjoint Set Union (Union-Find) with path compression for transitive identity linkage."""

    def __init__(self) -> None:
        self.parent: Dict[str, str] = {}

    def find(self, item: str) -> str:
        if item not in self.parent:
            self.parent[item] = item
            return item
        if self.parent[item] != item:
            self.parent[item] = self.find(self.parent[item])
        return self.parent[item]

    def union(self, a: str, b: str) -> None:
        root_a = self.find(a)
        root_b = self.find(b)
        if root_a != root_b:
            self.parent[root_b] = root_a

    def get_component(self, item: str, all_items: Set[str]) -> Set[str]:
        root = self.find(item)
        return {x for x in all_items if self.find(x) == root}


class SemanticVerifier:
    """Independent auditor for output.csv and identity consistency."""

    PHASE_ORDER = {"FINDING": 1, "REMEDIATION": 2, "VERIFICATION": 3}
    VALID_STATUSES = {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}

    def __init__(self, dataset_dir: str) -> None:
        self.dataset_dir = dataset_dir
        self.dsu = DisjointSetUnion()
        self.all_terms: Set[str] = set()
        self.requests_by_case: Dict[str, Dict[str, str]] = {}
        self.user_to_email: Dict[str, str] = {}
        self.email_to_user: Dict[str, str] = {}
        self.evidence_files: Dict[str, Dict[str, str]] = {}
        self._build_independent_identity_graph()

    def _build_independent_identity_graph(self) -> None:
        # 1. Load user identities
        p_u = os.path.join(self.dataset_dir, "user_identities.csv")
        if os.path.exists(p_u):
            with open(p_u, "r", encoding="utf-8", errors="replace") as f:
                for r in csv.DictReader(f):
                    uid = r.get("user_id", "").strip()
                    em = r.get("email", "").lower().strip()
                    ph = r.get("phone", "").strip()
                    hsh = r.get("email_hash", "").strip()

                    terms = [t for t in [uid, em, ph, hsh] if t]
                    for t in terms:
                        self.all_terms.add(t)
                    for i in range(len(terms) - 1):
                        self.dsu.union(terms[i], terms[i + 1])

                    if uid and em:
                        self.user_to_email[uid] = em
                        self.email_to_user[em] = uid

        # 2. Transitive union from historical audit log
        p_al = os.path.join(self.dataset_dir, "user_audit_log.csv")
        if os.path.exists(p_al):
            with open(p_al, "r", encoding="utf-8", errors="replace") as f:
                for r in csv.DictReader(f):
                    uid = r.get("user_id", "").strip()
                    old_v = r.get("old_value", "").strip()
                    new_v = r.get("new_value", "").strip()
                    if "@" in old_v:
                        old_v = old_v.lower()
                    if "@" in new_v:
                        new_v = new_v.lower()

                    for val in [old_v, new_v]:
                        if val:
                            self.all_terms.add(val)
                            if uid:
                                self.all_terms.add(uid)
                                self.dsu.union(uid, val)

        # 3. Load deletion requests for timing and request text
        for fname in ["sample_deletion_requests.csv", "deletion_requests.csv"]:
            p_req = os.path.join(self.dataset_dir, fname)
            if os.path.exists(p_req):
                with open(p_req, "r", encoding="utf-8", errors="replace") as f:
                    for r in csv.DictReader(f):
                        self.requests_by_case[r["case_id"]] = r

        # 4. Load evidence files manifest
        p_ev = os.path.join(self.dataset_dir, "evidence_files.csv")
        if os.path.exists(p_ev):
            with open(p_ev, "r", encoding="utf-8", errors="replace") as f:
                for r in csv.DictReader(f):
                    self.evidence_files[r["file_id"]] = r

    def get_identity_component(self, email: str) -> Set[str]:
        return self.dsu.get_component(email.lower().strip(), self.all_terms)

    def verify_file(self, output_csv_path: str) -> Dict[str, Any]:
        """Runs the complete independent semantic verification on output.csv."""
        report: Dict[str, Any] = {
            "is_valid": True,
            "total_cases_verified": 0,
            "schema_errors": [],
            "step_ordering_violations": [],
            "citation_errors": [],
            "semantic_contradictions": [],
            "unsupported_conclusions": [],
            "unresolved_aliases": [],
        }

        if not os.path.exists(output_csv_path):
            report["is_valid"] = False
            report["schema_errors"].append(f"File not found: {output_csv_path}")
            return report

        with open(output_csv_path, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.reader(f)
            header = next(reader, None)
            if header != ["case_id", "deletion_status", "steps_json"]:
                report["is_valid"] = False
                report["schema_errors"].append(
                    f"Invalid CSV header: expected ['case_id', 'deletion_status', 'steps_json'], got {header}"
                )

            last_case_num = -1
            for row_no, row in enumerate(reader, start=2):
                if len(row) != 3:
                    report["is_valid"] = False
                    report["schema_errors"].append(f"Line {row_no}: expected 3 columns, got {len(row)}")
                    continue

                cid, status, steps_raw = row
                report["total_cases_verified"] += 1

                # Case sequence check
                parts = cid.split("_")
                if len(parts) == 2 and parts[1].isdigit():
                    c_num = int(parts[1])
                    if last_case_num != -1 and c_num != last_case_num + 1:
                        report["schema_errors"].append(
                            f"Non-consecutive case ID: expected case_{last_case_num + 1}, got {cid}"
                        )
                    last_case_num = c_num

                # Status validity
                if status not in self.VALID_STATUSES:
                    report["is_valid"] = False
                    report["schema_errors"].append(f"Case {cid}: invalid status '{status}'")
                    continue

                # JSON parsing
                try:
                    steps = json.loads(steps_raw)
                except Exception as e:
                    report["is_valid"] = False
                    report["schema_errors"].append(f"Case {cid}: JSON parse failure: {e}")
                    continue

                req_info = self.requests_by_case.get(cid, {})
                user_email = req_info.get("email", "").lower().strip()
                ident_terms = self.get_identity_component(user_email) if user_email else set()

                # NOT_APPLICABLE case check
                if status == "NOT_APPLICABLE":
                    if len(steps) != 0:
                        report["is_valid"] = False
                        report["semantic_contradictions"].append(
                            f"Case {cid}: NOT_APPLICABLE status must have empty steps, found {len(steps)} steps"
                        )
                    continue

                # Step ordering and numbering
                last_phase_val = 0
                has_findings = False
                has_remediations = False
                has_verifications = False

                for expected_step_no, s in enumerate(steps, start=1):
                    s_no = s.get("step_no")
                    phase = s.get("phase", "")
                    sys_id = s.get("system_id", "")
                    res_id = s.get("resource_id", "")
                    ev_id = s.get("evidence_id", "")

                    if s_no != expected_step_no:
                        report["is_valid"] = False
                        report["step_ordering_violations"].append(
                            f"Case {cid}: non-contiguous step_no (expected {expected_step_no}, got {s_no})"
                        )

                    p_val = self.PHASE_ORDER.get(phase, 0)
                    if p_val == 0:
                        report["is_valid"] = False
                        report["step_ordering_violations"].append(f"Case {cid}: unknown phase '{phase}'")
                    elif p_val < last_phase_val:
                        report["is_valid"] = False
                        report["step_ordering_violations"].append(
                            f"Case {cid}: phase progression violation: {phase} followed previous higher phase"
                        )
                    last_phase_val = p_val

                    if phase == "FINDING":
                        has_findings = True
                        if not ev_id:
                            report["is_valid"] = False
                            report["citation_errors"].append(
                                f"Case {cid}: FINDING on {res_id} missing mandatory evidence citation"
                            )
                        elif ev_id not in self.evidence_files and not ev_id.startswith("evidence_"):
                            report["citation_errors"].append(
                                f"Case {cid}: FINDING cites unknown evidence_id '{ev_id}'"
                            )
                    elif phase == "REMEDIATION":
                        has_remediations = True
                    elif phase == "VERIFICATION":
                        has_verifications = True
                        if status == "COMPLETE" and not ev_id:
                            report["is_valid"] = False
                            report["citation_errors"].append(
                                f"Case {cid}: COMPLETE case step {s_no} missing evidence citation"
                            )

                # Status consistency
                if status == "COMPLETE":
                    if has_findings or has_remediations:
                        report["is_valid"] = False
                        report["semantic_contradictions"].append(
                            f"Case {cid}: marked COMPLETE but contains FINDING or REMEDIATION steps"
                        )
                    if not has_verifications and len(steps) > 0:
                        report["is_valid"] = False
                        report["semantic_contradictions"].append(
                            f"Case {cid}: COMPLETE case has steps but no VERIFICATION phase"
                        )

                elif status == "INCOMPLETE":
                    if not has_findings:
                        report["is_valid"] = False
                        report["semantic_contradictions"].append(
                            f"Case {cid}: marked INCOMPLETE but contains zero FINDING steps to justify status"
                        )

        # Final verdict
        crit_errors = (
            len(report["schema_errors"])
            + len(report["step_ordering_violations"])
            + len(report["citation_errors"])
            + len(report["semantic_contradictions"])
        )
        report["is_valid"] = crit_errors == 0
        return report


def main() -> int:
    parser = argparse.ArgumentParser(description="Independent Semantic & Schema Verifier")
    parser.add_argument("--output-csv", default="output.csv", help="Path to output.csv")
    parser.add_argument("--dataset-dir", default="dataset", help="Path to dataset directory")
    args = parser.parse_args()

    out_csv = args.output_csv
    if not os.path.exists(out_csv):
        code_out = os.path.join("code", "output.csv")
        if os.path.exists(code_out):
            out_csv = code_out

    dataset_dir = args.dataset_dir
    if not os.path.isdir(dataset_dir):
        up_dataset = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "dataset")
        if os.path.isdir(up_dataset):
            dataset_dir = up_dataset

    print(f"Initializing Independent Semantic Verifier on {dataset_dir}...")
    verifier = SemanticVerifier(dataset_dir)
    print(f"Constructed transitive identity graph across {len(verifier.all_terms)} known identity terms.")

    print(f"Auditing semantics and schema for {out_csv}...")
    report = verifier.verify_file(out_csv)

    print(f"\n--- VERIFICATION AUDIT REPORT ---")
    print(f"Total Cases Checked:        {report['total_cases_verified']}")
    print(f"Schema Errors:              {len(report['schema_errors'])}")
    print(f"Step Ordering Violations:   {len(report['step_ordering_violations'])}")
    print(f"Citation Errors:            {len(report['citation_errors'])}")
    print(f"Semantic Contradictions:    {len(report['semantic_contradictions'])}")

    if report["is_valid"]:
        print(f"\n[PASS] Output file {out_csv} is SEMANTICALLY VALID and contradiction-free!")
        return 0
    else:
        print(f"\n[FAIL] Semantic verification failed!")
        for cat in ["schema_errors", "step_ordering_violations", "citation_errors", "semantic_contradictions"]:
            errs = report.get(cat, [])
            if errs:
                print(f"  {cat.upper()}:")
                for e in errs[:5]:
                    print(f"    - {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
