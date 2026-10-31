"""
Shadow PII Heuristic Scanner
HackerRank Orchestrate - Ghost Data Still Exists

Scans evidence files deterministically for potential unindexed or orphaned PII traces.
Utilizes regular expression patterns, cryptographic hash correlation, and Shannon
entropy analysis to flag suspicious identifiers.

Privacy & Ethical Safeguards:
- Matches are treated strictly as heuristic indicators warranting audit review, not
  conclusive legal proof of an individual user's identity.
- Masked reporting: Raw PII is redacted/masked in generated reports to prevent secondary leakage.
- Non-destructive: Evidence files are opened strictly read-only.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

# Pre-compiled regular expressions for pattern detection
RE_EMAIL = re.compile(r"\b([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)\b")
RE_SHA256 = re.compile(r"\b([a-fA-F0-9]{64})\b")
RE_MD5 = re.compile(r"\b([a-fA-F0-9]{32})\b")
RE_PHONE = re.compile(r"(\+\d{1,3}[\s-]?\(?\d{2,4}\)?[\s-]?\d{3,4}[\s-]?\d{3,4})")
RE_HIGH_ENTROPY_CANDIDATE = re.compile(r"\b([A-Za-z0-9+/=_-]{20,80})\b")


def compute_shannon_entropy(data_str: str) -> float:
    """Calculates Shannon entropy in bits per character for a string."""
    if not data_str:
        return 0.0
    length = len(data_str)
    counts = Counter(data_str)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def mask_pii(pattern_type: str, raw_value: str) -> str:
    """Masks sensitive parts of detected values to prevent secondary PII leakage in reports."""
    if pattern_type == "EMAIL":
        parts = raw_value.split("@")
        if len(parts) == 2:
            name, domain = parts
            masked_name = name[0] + "***" if len(name) > 1 else "***"
            return f"{masked_name}@{domain}"
        return "***@***"
    elif pattern_type in ("SHA256_HASH", "KNOWN_EMAIL_SHA256", "MD5_HASH", "KNOWN_EMAIL_MD5"):
        return f"{raw_value[:8]}...[MASKED]"
    elif pattern_type == "PHONE":
        return f"{raw_value[:4]} *** {raw_value[-4:]}" if len(raw_value) > 8 else "***-***"
    elif pattern_type == "HIGH_ENTROPY_TOKEN":
        return f"{raw_value[:6]}...[MASKED]"
    return "[MASKED]"


class ShadowPIIScanner:
    """Deterministic scanner for detecting potential PII and correlation hashes."""

    def __init__(self, dataset_dir: Optional[str] = None) -> None:
        self.known_email_hashes_sha256: Dict[str, str] = {}
        self.known_email_hashes_md5: Dict[str, str] = {}
        if dataset_dir:
            self._load_known_identities(dataset_dir)

    def _load_known_identities(self, dataset_dir: str) -> None:
        p_u = os.path.join(dataset_dir, "user_identities.csv")
        if os.path.exists(p_u):
            with open(p_u, "r", encoding="utf-8", errors="replace") as f:
                for r in csv.DictReader(f):
                    em = r.get("email", "").lower().strip()
                    if em:
                        sha = hashlib.sha256(em.encode("utf-8")).hexdigest()
                        md5 = hashlib.md5(em.encode("utf-8")).hexdigest()
                        self.known_email_hashes_sha256[sha] = em
                        self.known_email_hashes_md5[md5] = em

    def scan_text(self, text: str, file_path: str) -> List[Dict[str, Any]]:
        """Scans a text payload and returns detected indicators with metadata."""
        findings: List[Dict[str, Any]] = []
        lines = text.splitlines()

        for line_no, line in enumerate(lines, start=1):
            # 1. Email matches
            for em in RE_EMAIL.findall(line):
                findings.append({
                    "file": file_path,
                    "line": line_no,
                    "pattern_type": "EMAIL",
                    "confidence": "HIGH",
                    "masked_indicator": mask_pii("EMAIL", em),
                    "context": f"Observed email format in line {line_no}",
                })

            # 2. SHA-256 matches (distinguishing known email hashes vs generic hash)
            for h64 in RE_SHA256.findall(line):
                h64_lower = h64.lower()
                if h64_lower in self.known_email_hashes_sha256:
                    findings.append({
                        "file": file_path,
                        "line": line_no,
                        "pattern_type": "KNOWN_EMAIL_SHA256",
                        "confidence": "HIGH",
                        "masked_indicator": mask_pii("KNOWN_EMAIL_SHA256", h64),
                        "context": "Cryptographic match for registered user identity email",
                    })
                else:
                    findings.append({
                        "file": file_path,
                        "line": line_no,
                        "pattern_type": "SHA256_HASH",
                        "confidence": "MEDIUM",
                        "masked_indicator": mask_pii("SHA256_HASH", h64),
                        "context": "Generic 64-hex SHA-256 hash candidate",
                    })

            # 3. MD5 matches
            for h32 in RE_MD5.findall(line):
                h32_lower = h32.lower()
                if h32_lower in self.known_email_hashes_md5:
                    findings.append({
                        "file": file_path,
                        "line": line_no,
                        "pattern_type": "KNOWN_EMAIL_MD5",
                        "confidence": "HIGH",
                        "masked_indicator": mask_pii("KNOWN_EMAIL_MD5", h32),
                        "context": "Cryptographic match for registered user identity email (MD5)",
                    })

            # 4. Phone numbers
            for ph in RE_PHONE.findall(line):
                # Basic length and digit check
                digits = [c for c in ph if c.isdigit()]
                if 8 <= len(digits) <= 15:
                    findings.append({
                        "file": file_path,
                        "line": line_no,
                        "pattern_type": "PHONE",
                        "confidence": "MEDIUM",
                        "masked_indicator": mask_pii("PHONE", ph),
                        "context": "E.164 or regional telephone format",
                    })

            # 5. Shannon entropy analysis on tokens
            for tok in RE_HIGH_ENTROPY_CANDIDATE.findall(line):
                ent = compute_shannon_entropy(tok)
                # Typical base64 / token strings have entropy > 4.2 bits/char
                if ent >= 4.2 and not RE_SHA256.fullmatch(tok) and not RE_MD5.fullmatch(tok):
                    findings.append({
                        "file": file_path,
                        "line": line_no,
                        "pattern_type": "HIGH_ENTROPY_TOKEN",
                        "confidence": "LOW",
                        "masked_indicator": mask_pii("HIGH_ENTROPY_TOKEN", tok),
                        "context": f"Entropy: {ent:.2f} bits/char (potential secret or opaque key)",
                    })

        return findings

    def scan_directory(self, evidence_dir: str, limit_files: Optional[int] = None) -> Dict[str, Any]:
        """Scans all supported files in the evidence directory."""
        all_findings: List[Dict[str, Any]] = []
        scanned_files = 0
        skipped_files = 0

        supported_exts = {".log", ".sql", ".txt", ".json", ".csv"}

        files_to_scan: List[str] = []
        for root, _, files in os.walk(evidence_dir):
            for f in sorted(files):
                ext = os.path.splitext(f)[1].lower()
                if ext in supported_exts:
                    files_to_scan.append(os.path.join(root, f))

        if limit_files:
            files_to_scan = files_to_scan[:limit_files]

        for p in files_to_scan:
            rel_p = os.path.relpath(p, evidence_dir)
            try:
                with open(p, "r", encoding="utf-8", errors="replace") as fh:
                    content = fh.read()
                file_findings = self.scan_text(content, rel_p)
                all_findings.extend(file_findings)
                scanned_files += 1
            except Exception:
                skipped_files += 1

        # Summary statistics
        by_type: Dict[str, int] = Counter(f["pattern_type"] for f in all_findings)
        by_conf: Dict[str, int] = Counter(f["confidence"] for f in all_findings)

        report = {
            "scanner_version": "1.0.0",
            "scan_timestamp": datetime.now(timezone.utc).isoformat(),
            "target_directory": evidence_dir,
            "scanned_files": scanned_files,
            "skipped_files": skipped_files,
            "total_indicators": len(all_findings),
            "indicators_by_type": dict(by_type),
            "indicators_by_confidence": dict(by_conf),
            "disclaimer": (
                "Matches are suspicious heuristic indicators warranting human/audit review, "
                "not definitive proof of an individual's personal identity."
            ),
            "findings_sample": all_findings[:150],  # Keep report compact and masked
        }

        return report


def main() -> int:
    parser = argparse.ArgumentParser(description="Deterministic Shadow PII Heuristic Scanner")
    parser.add_argument("--evidence-dir", default="dataset/evidence", help="Path to evidence directory")
    parser.add_argument("--dataset-dir", default="dataset", help="Path to dataset directory")
    parser.add_argument("--out", default="shadow_pii_report.json", help="Path for JSON scan report")
    parser.add_argument("--max-files", type=int, default=None, help="Optional max files limit")
    args = parser.parse_args()

    ev_dir = args.evidence_dir
    if not os.path.isdir(ev_dir):
        # Fallback search
        candidate = os.path.join("dataset", "evidence")
        if os.path.isdir(candidate):
            ev_dir = candidate
        else:
            print(f"[ERROR] Evidence directory not found: {ev_dir}")
            return 1

    dataset_dir = args.dataset_dir
    if not os.path.isdir(dataset_dir):
        dataset_dir = os.path.dirname(ev_dir)

    print(f"Initializing Shadow PII Scanner on {ev_dir}...")
    scanner = ShadowPIIScanner(dataset_dir)
    print(f"Pre-loaded {len(scanner.known_email_hashes_sha256)} known identity hash signatures.")

    report = scanner.scan_directory(ev_dir, limit_files=args.max_files)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"[SUCCESS] Scan completed across {report['scanned_files']} files.")
    print(f"Total Indicators Found: {report['total_indicators']}")
    print(f"By Confidence: {report['indicators_by_confidence']}")
    print(f"By Type:       {report['indicators_by_type']}")
    print(f"Report written to: {os.path.abspath(args.out)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
