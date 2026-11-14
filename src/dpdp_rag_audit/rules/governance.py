from __future__ import annotations

import json
from typing import Any, Dict, List
from .base import PrivacyViolation, Severity


def scan_metadata_compliance(metadata: Dict[str, Any]) -> List[PrivacyViolation]:
    """Lints metadata associated with a vector embedding or chunk for DPDP & GDPR compliance."""
    violations: List[PrivacyViolation] = []

    # 1. Missing Consent Verification (DPDP Act Sec 6 & GDPR Art 6)
    if "consent_verified" not in metadata or not metadata.get("consent_verified"):
        violations.append(
            PrivacyViolation(
                rule_id="DPDP-GOV-01",
                law_reference="DPDP Act 2023 Sec 6(1) & GDPR Art 6",
                identifier_type="Consent Metadata",
                severity=Severity.HIGH,
                matched_value="consent_verified: missing/false",
                char_span=(0, 0),
                description="Chunk metadata lacks verified consent flag for retrieval-augmented generation.",
                remediation="Attach 'consent_verified: true' to metadata after validating user consent record.",
            )
        )

    # 2. Missing Purpose Specification (DPDP Act Sec 4 & GDPR Art 5(1)(b))
    if "purpose" not in metadata or not str(metadata.get("purpose", "")).strip():
        violations.append(
            PrivacyViolation(
                rule_id="DPDP-GOV-02",
                law_reference="DPDP Act 2023 Sec 4(1)(a) (Purpose Limitation)",
                identifier_type="Purpose Specification",
                severity=Severity.MEDIUM,
                matched_value="purpose: unspecified",
                char_span=(0, 0),
                description="Document chunk indexed without specified processing purpose.",
                remediation="Specify declared purpose in chunk metadata (e.g., 'purpose': 'customer_support_qna').",
            )
        )

    return violations
