from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Tuple


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class PrivacyViolation:
    rule_id: str
    law_reference: str  # e.g. "DPDP Act 2023 Sec 4"
    identifier_type: str
    severity: Severity
    matched_value: str
    char_span: Tuple[int, int]
    description: str
    remediation: str

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "law_reference": self.law_reference,
            "identifier_type": self.identifier_type,
            "severity": self.severity.value,
            "matched_value": self.matched_value,
            "char_span": list(self.char_span),
            "description": self.description,
            "remediation": self.remediation,
        }
