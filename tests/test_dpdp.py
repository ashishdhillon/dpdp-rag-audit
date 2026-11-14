import unittest
from dpdp_rag_audit.verhoeff import validate_verhoeff, verhoeff_check_digit
from dpdp_rag_audit.rules.identifiers import scan_identifiers
from dpdp_rag_audit.rules.governance import scan_metadata_compliance
from dpdp_rag_audit.scanner import DPDPScanner
from dpdp_rag_audit.redactor import redact_identifiers


class TestDPDPAudit(unittest.TestCase):
    def test_verhoeff_checksum(self):
        valid_num = "23456789012" + verhoeff_check_digit("23456789012")
        self.assertTrue(validate_verhoeff(valid_num))
        # Invalid
        self.assertFalse(validate_verhoeff("123456789012"))

    def test_identifier_scanner(self):
        valid_aadhaar = "2345 6789 012" + verhoeff_check_digit("23456789012")
        text = f"Client PAN: ABCDE1234F, Aadhaar: {valid_aadhaar}, Phone: 9876543210."
        violations = scan_identifiers(text)
        types = [v.identifier_type for v in violations]
        self.assertIn("PAN Number", types)
        self.assertIn("Aadhaar Number", types)
        self.assertIn("Indian Mobile Number", types)

    def test_metadata_linter(self):
        meta_bad = {}
        v_bad = scan_metadata_compliance(meta_bad)
        self.assertEqual(len(v_bad), 2)  # consent & purpose missing

        meta_good = {"consent_verified": True, "purpose": "billing_qna"}
        v_good = scan_metadata_compliance(meta_good)
        self.assertEqual(len(v_good), 0)

    def test_redactor(self):
        valid_aadhaar = "23456789012" + verhoeff_check_digit("23456789012")
        raw = f"User with Aadhaar {valid_aadhaar}, PAN ABCDE1234F and phone 9876543210 sent funds via user@okaxis."
        cleaned, count = redact_identifiers(raw)
        self.assertNotIn(valid_aadhaar, cleaned)
        self.assertNotIn("ABCDE1234F", cleaned)
        self.assertNotIn("9876543210", cleaned)
        self.assertIn("[REDACTED:AADHAAR]", cleaned)
        self.assertIn("[REDACTED:PAN]", cleaned)
        self.assertIn("[REDACTED:PHONE]", cleaned)
        self.assertIn("[REDACTED:UPI]", cleaned)
        self.assertEqual(count, 4)

    def test_voter_and_dl_detection(self):
        text = "Voter ID: ABC1234567, Driving License: DL-0420110149646."
        violations = scan_identifiers(text)
        types = [v.identifier_type for v in violations]
        self.assertIn("Voter ID (EPIC)", types)
        self.assertIn("Driving License", types)

        cleaned, count = redact_identifiers(text)
        self.assertIn("[REDACTED:VOTER_ID]", cleaned)
        self.assertIn("[REDACTED:DRIVING_LICENSE]", cleaned)
        self.assertEqual(count, 2)

    def test_invalid_dl_state_code(self):
        # ZZ is not a valid Indian state code
        text = "Fake license: ZZ-0420110149646"
        violations = scan_identifiers(text)
        types = [v.identifier_type for v in violations]
        self.assertNotIn("Driving License", types)

    def test_scanner_corpus(self):
        scanner = DPDPScanner()
        items = [
            ("Safe technical text without PII.", {"consent_verified": True, "purpose": "docs"}),
            ("Contact 9876543210 for support.", None),
        ]
        report = scanner.scan_corpus(items)
        self.assertEqual(report.total_items_scanned, 2)
        self.assertEqual(report.compliant_items, 1)
        self.assertGreater(len(report.violations), 0)


if __name__ == "__main__":
    unittest.main()
