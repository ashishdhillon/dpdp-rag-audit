"""DPDP RAG Audit: Compliance Linter for RAG Knowledge Bases."""

from .rules.base import PrivacyViolation, Severity
from .rules.identifiers import scan_identifiers
from .rules.governance import scan_metadata_compliance
from .scanner import DPDPScanner, ScanReport
from .redactor import redact_identifiers
from .verhoeff import validate_verhoeff

__version__ = "0.1.0"

__all__ = [
    "PrivacyViolation",
    "Severity",
    "scan_identifiers",
    "scan_metadata_compliance",
    "DPDPScanner",
    "ScanReport",
    "redact_identifiers",
    "validate_verhoeff",
]
