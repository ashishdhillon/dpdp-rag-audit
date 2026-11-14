from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List
from .rules.base import PrivacyViolation, Severity
from .rules.identifiers import scan_identifiers
from .rules.governance import scan_metadata_compliance


@dataclass
class ScanReport:
    total_items_scanned: int
    compliant_items: int
    violations: List[PrivacyViolation] = field(default_factory=list)
    status: str = "COMPLIANT"  # COMPLIANT, PARTIALLY_COMPLIANT, NON_COMPLIANT

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_items_scanned": self.total_items_scanned,
            "compliant_items": self.compliant_items,
            "violation_count": len(self.violations),
            "status": self.status,
            "violations": [v.to_dict() for v in self.violations],
        }


class DPDPScanner:
    """Scanner for detecting Indian Personal Data violations in RAG corpora."""

    def scan_chunk(
        self,
        text: str,
        metadata: Dict[str, Any] | None = None,
    ) -> List[PrivacyViolation]:
        violations = scan_identifiers(text)
        if metadata is not None:
            violations.extend(scan_metadata_compliance(metadata))
        return violations

    def scan_corpus(
        self,
        items: List[tuple[str, Dict[str, Any] | None]],
    ) -> ScanReport:
        all_violations: List[PrivacyViolation] = []
        compliant_count = 0

        for text, meta in items:
            v_list = self.scan_chunk(text, meta)
            if not v_list:
                compliant_count += 1
            else:
                all_violations.extend(v_list)

        has_critical_or_high = any(
            v.severity in (Severity.CRITICAL, Severity.HIGH) for v in all_violations
        )
        if not all_violations:
            status = "COMPLIANT"
        elif has_critical_or_high:
            status = "NON_COMPLIANT"
        else:
            status = "PARTIALLY_COMPLIANT"

        return ScanReport(
            total_items_scanned=len(items),
            compliant_items=compliant_count,
            violations=all_violations,
            status=status,
        )


def format_table(report: ScanReport) -> str:
    lines = [
        "┌────────────────────────────────────────────────────────────┐",
        "│              DPDP & GDPR RAG COMPLIANCE AUDIT              │",
        "├────────────────────────────────────────────────────────────┤",
        f"│ Scanned Chunks: {report.total_items_scanned:<5} Compliant: {report.compliant_items:<5} Violations: {len(report.violations):<5} │",
        f"│ Compliance Status: {report.status:<39} │",
        "├────────────────────────────────────────────────────────────┤",
    ]
    if not report.violations:
        lines.append("│ ✅ No personal identifiers or consent violations detected. │")
    else:
        lines.append("│ Privacy Deficiencies Identified:                           │")
        for idx, v in enumerate(report.violations[:10], 1):
            lines.append(f"│  {idx}. [{v.severity.value.upper()}] {v.identifier_type:<20} ({v.rule_id})     │")
            lines.append(f"│     Found: {v.matched_value:<47} │")
    lines.append("└────────────────────────────────────────────────────────────┘")
    return "\n".join(lines)


def format_markdown(report: ScanReport) -> str:
    lines = [
        "# DPDP Act (2023) & GDPR RAG Compliance Audit Report",
        "",
        f"- **Compliance Status:** **`{report.status}`**",
        f"- **Total Chunks Inspected:** `{report.total_items_scanned}`",
        f"- **Compliant Chunks:** `{report.compliant_items}`",
        f"- **Privacy Deficiencies:** `{len(report.violations)}`",
        "",
        "## Identified Deficiencies",
        "",
        "| Rule ID | Identifier / Category | Severity | Legal Reference | Value |",
        "| :--- | :--- | :--- | :--- | :--- |",
    ]
    for v in report.violations:
        lines.append(
            f"| `{v.rule_id}` | `{v.identifier_type}` | `{v.severity.value.upper()}` | {v.law_reference} | `{v.matched_value}` |"
        )
    return "\n".join(lines)
