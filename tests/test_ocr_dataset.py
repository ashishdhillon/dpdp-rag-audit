import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from dpdp_rag_audit.rules.identifiers import scan_identifiers
from dpdp_rag_audit.redactor import redact_identifiers
from dpdp_rag_audit.verhoeff import verhoeff_check_digit

# Generate valid test Aadhaar
_A1 = "23456789012" + verhoeff_check_digit("23456789012")
_A2 = "98765432109" + verhoeff_check_digit("98765432109")

NOISY_OCR_SAMPLES = [
    # 1. Loan application with spaced PAN
    ("Applicant Details: Name: Suresh Verma, PAN: ABCDE 9876 F, Income: 12 LPA.", ["PAN Number"]),
    # 2. KYC upload with 4-4-4 Aadhaar
    (f"Identity Verification: Aadhaar Card attached: {_A1[:4]} {_A1[4:8]} {_A1[8:]}.", ["Aadhaar Number"]),
    # 3. Hyphenated Aadhaar
    (f"KYC Document No: {_A2[:4]}-{_A2[4:8]}-{_A2[8:]} confirmed verified.", ["Aadhaar Number"]),
    # 4. GSTIN invoice line
    ("Vendor Billing: M/S Tech Solutions, GSTIN: 07AAAAA0000A1Z5, Amount: 45,000 INR.", ["GSTIN"]),
    # 5. Customer support mobile with country code
    ("User reported login issue via phone +91 9876543210 on Monday morning.", ["Indian Mobile Number"]),
    # 6. Unspaced mobile
    ("Callback requested at 8123456789 between 2 PM and 4 PM.", ["Indian Mobile Number"]),
    # 7. UPI payment issue
    ("Refund transaction failed for VPA customer.care@okicici on gateway switch.", ["UPI Handle"]),
    # 8. Voter ID in election verification
    ("EPIC Card submitted: WXY9876543, Constituency: Bangalore South.", ["Voter ID (EPIC)"]),
    # 9. Hyphenated Voter ID
    ("Voter credential verified: DLX-1234567 during voter roll audit.", ["Voter ID (EPIC)"]),
    # 10. Driving License Delhi state code
    ("Driver verification: License DL-0420110149646 valid up to 2031.", ["Driving License"]),
    # 11. Driving License Maharashtra state code
    ("Courier onboarding: MH12 20180012345 commercial transport badge.", ["Driving License"]),
    # 12. Combined KYC record (Aadhaar + PAN + Mobile)
    (f"Executive dossier: PAN: FGHIJ-1234-K, Aadhaar: {_A1}, Mobile: 9811223344.", ["PAN Number", "Aadhaar Number", "Indian Mobile Number"]),
    # 13. Mixed case with OCR newline
    ("Customer Record:\nPAN: KLMNO4321P\nUPI: arjun.sharma@paytm", ["PAN Number", "UPI Handle"]),
    # 14. Driving License Karnataka
    ("Chauffeur service: Driver ID KA01 20200098765 assigned to route.", ["Driving License"]),
    # 15. Dotted Aadhaar in OCR table
    (f"Table row 4 | {_A2[:4]}.{_A2[4:8]}.{_A2[8:]} | Verified | Net banking active", ["Aadhaar Number"]),
]


class TestOCRDataset(unittest.TestCase):
    def test_all_ocr_samples_detected(self):
        for idx, (text, expected_types) in enumerate(NOISY_OCR_SAMPLES, 1):
            violations = scan_identifiers(text)
            detected_types = [v.identifier_type for v in violations]
            for exp in expected_types:
                self.assertIn(
                    exp,
                    detected_types,
                    f"Sample #{idx} failed to detect {exp} in text: '{text}' (detected: {detected_types})",
                )

    def test_all_ocr_samples_redacted(self):
        for idx, (text, expected_types) in enumerate(NOISY_OCR_SAMPLES, 1):
            cleaned, count = redact_identifiers(text)
            self.assertGreater(
                count, 0, f"Sample #{idx} expected redactions but count was 0"
            )


if __name__ == "__main__":
    unittest.main()
