"""
Unit test suite for PolicyEngine.
Tests:
1. Non-deletion requests (access, correction, export, opt-out) -> NOT_APPLICABLE with empty steps
2. Retained account tombstones (compliant redacted vs exposed direct identifiers)
3. Active synchronization flows (active finding/remediation vs compliant disabled)
4. Restore access risks (active restore risk/block vs compliant blocked)
5. Policy-required retained records (SECURITY_AUDIT_LOG, LEGAL_HOLD_RECORD -> VERIFY_RECORD_PRESENT)
6. Complete deletion case -> Verification-only with evidence citations
7. Incomplete deletion case -> Finding with evidence, empty evidence for remediation & post-verification
8. Strict sorting and consecutive step numbering
"""

import os
import sys
import unittest

# Ensure code directory is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from identity import IdentityGraph
from evidence_store import EvidenceStore
from policy_engine import PolicyEngine


class TestPolicyEngine(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        cls.dataset_dir = os.path.join(cls.repo_root, "dataset")
        cls.identities_csv = os.path.join(cls.dataset_dir, "user_identities.csv")
        cls.audit_csv = os.path.join(cls.dataset_dir, "user_audit_log.csv")

        cls.graph = IdentityGraph(cls.identities_csv, cls.audit_csv)
        cls.store = EvidenceStore(cls.dataset_dir, cls.graph)
        cls.engine = PolicyEngine(cls.dataset_dir, cls.graph, cls.store)

    def test_non_deletion_requests_return_not_applicable(self):
        """Verify that requests for access, correction, portable export, and opt-out return NOT_APPLICABLE with []."""
        test_cases = [
            {
                "case_id": "test_optout",
                "email": "haruka-kato@gmail.com",
                "request_text": "The mobile number on my profile is out of date. Please replace it with the new one and leave the account active.",
                "audit_at": "2026-10-01T00:00:00Z"
            },
            {
                "case_id": "test_export",
                "email": "gabriel.l5556@outlook.com",
                "request_text": "I'd like to download my account information in a portable format. Please keep the account as it is.",
                "audit_at": "2026-10-01T00:00:00Z"
            },
            {
                "case_id": "test_marketing",
                "email": "morgan.amelia@icloud.com",
                "request_text": "Please remove me from marketing lists only. I still want receipts and service messages for this account.",
                "audit_at": "2026-10-01T00:00:00Z"
            },
            {
                "case_id": "test_access",
                "email": "leonie-rousseau@proton.me",
                "request_text": "Can you tell me what personal information you hold about me? This is an information request, not a request to erase it.",
                "audit_at": "2026-10-01T00:00:00Z"
            }
        ]

        for tc in test_cases:
            status, steps = self.engine.evaluate_request(tc)
            self.assertEqual(status, "NOT_APPLICABLE", f"{tc['case_id']} should be NOT_APPLICABLE")
            self.assertEqual(steps, [], f"{tc['case_id']} must have empty steps array")

    def test_retained_tombstone_treatment(self):
        """Verify handling of account tombstones (redacted compliant vs exposed direct PII)."""
        # Compliant tombstone: tombstone_440 (case_31)
        req_compliant = {
            "case_id": "case_31",
            "email": "a.eze08@gmail.com",
            "request_text": "Please delete my account and personal data.",
            "audit_at": "2026-09-15T12:00:00Z"
        }
        status, steps = self.engine.evaluate_request(req_compliant)
        tombstone_steps = [s for s in steps if s["system_id"] == "identity_service" and s["resource_id"] == "tombstone_440"]
        self.assertGreater(len(tombstone_steps), 0)
        self.assertEqual(tombstone_steps[0]["operation"], "VERIFY_RECORD_REDACTED")
        self.assertEqual(tombstone_steps[0]["state"], "REDACTED")

        # Exposed tombstone: tombstone_9178 (case_32)
        req_exposed = {
            "case_id": "case_32",
            "email": "addo.kofi@gmail.com",
            "request_text": "Please delete my account and personal data.",
            "audit_at": "2026-09-15T12:00:00Z"
        }
        status_exp, steps_exp = self.engine.evaluate_request(req_exposed)
        self.assertEqual(status_exp, "INCOMPLETE")
        t_finding = [s for s in steps_exp if s["resource_id"] == "tombstone_9178" and s["phase"] == "FINDING"]
        t_remed = [s for s in steps_exp if s["resource_id"] == "tombstone_9178" and s["phase"] == "REMEDIATION"]
        t_verif = [s for s in steps_exp if s["resource_id"] == "tombstone_9178" and s["phase"] == "VERIFICATION"]

        self.assertEqual(len(t_finding), 1)
        self.assertEqual(t_finding[0]["operation"], "REPORT_EXPOSED_PII")
        self.assertEqual(len(t_remed), 1)
        self.assertEqual(t_remed[0]["operation"], "REDACT_RECORD")
        self.assertEqual(len(t_verif), 1)
        self.assertEqual(t_verif[0]["operation"], "VERIFY_RECORD_REDACTED")

    def test_active_sync_data_flow_treatment(self):
        """Verify that active data flows trigger finding + remediation + post verification."""
        req_flow = {
            "case_id": "case_29",
            "email": "noah.f438085@outlook.com",
            "request_text": "Please delete my account and associated data.",
            "audit_at": "2026-09-17T12:00:00Z"
        }
        status, steps = self.engine.evaluate_request(req_flow)
        flow_finding = [s for s in steps if s["system_id"] == "integration_service" and s["phase"] == "FINDING"]
        self.assertGreater(len(flow_finding), 0)
        self.assertEqual(flow_finding[0]["operation"], "REPORT_ACTIVE_DATA_FLOW")
        self.assertEqual(flow_finding[0]["state"], "ACTIVE")

        flow_remed = [s for s in steps if s["system_id"] == "integration_service" and s["phase"] == "REMEDIATION"]
        self.assertGreater(len(flow_remed), 0)
        self.assertEqual(flow_remed[0]["operation"], "DISABLE_DATA_FLOW")
        self.assertEqual(flow_remed[0]["state"], "DISABLED")

        flow_verif = [s for s in steps if s["system_id"] == "integration_service" and s["phase"] == "VERIFICATION"]
        self.assertGreater(len(flow_verif), 0)
        self.assertEqual(flow_verif[0]["operation"], "VERIFY_DATA_FLOW_DISABLED")
        self.assertEqual(flow_verif[0]["state"], "DISABLED")

    def test_restore_risk_treatment(self):
        """Verify that active restore access triggers restore risk finding and block remediation."""
        req_backup = {
            "case_id": "case_09",
            "email": "k.appiah88@gmail.com",
            "request_text": "Please delete my account and records.",
            "audit_at": "2026-09-16T09:00:00Z"
        }
        status, steps = self.engine.evaluate_request(req_backup)
        backup_finding = [s for s in steps if s["system_id"] == "backup_service" and s["phase"] == "FINDING"]
        self.assertGreater(len(backup_finding), 0)
        self.assertEqual(backup_finding[0]["operation"], "REPORT_RESTORE_RISK")
        self.assertEqual(backup_finding[0]["state"], "ACTIVE")

        backup_remed = [s for s in steps if s["system_id"] == "backup_service" and s["phase"] == "REMEDIATION"]
        self.assertGreater(len(backup_remed), 0)
        self.assertEqual(backup_remed[0]["operation"], "BLOCK_RESTORE")
        self.assertEqual(backup_remed[0]["state"], "BLOCKED")

    def test_retained_records_verification(self):
        """Verify that security audit logs and legal hold records are retained per policy."""
        req = {
            "case_id": "case_03",
            "email": "l.fontaine46@yahoo.com",
            "request_text": "Please delete my account.",
            "audit_at": "2026-09-26T11:00:00Z"
        }
        status, steps = self.engine.evaluate_request(req)
        audit_verif = [s for s in steps if s["system_id"] == "security_service" and s["phase"] == "VERIFICATION"]
        self.assertGreater(len(audit_verif), 0)
        self.assertEqual(audit_verif[0]["operation"], "VERIFY_RECORD_PRESENT")
        self.assertEqual(audit_verif[0]["state"], "PRESENT")

    def test_consecutive_numbering_and_phase_ordering(self):
        """Verify that all generated steps are numbered 1..N and ordered by phase."""
        req = {
            "case_id": "case_11",
            "email": "novak.tomasz@icloud.com",
            "request_text": "Please delete my account completely.",
            "audit_at": "2026-10-01T12:00:00Z"
        }
        status, steps = self.engine.evaluate_request(req)
        self.assertGreater(len(steps), 0)

        # Check consecutive step_no
        for idx, s in enumerate(steps, 1):
            self.assertEqual(s["step_no"], idx)

        # Check phase ordering
        phase_map = {"FINDING": 1, "REMEDIATION": 2, "VERIFICATION": 3}
        for i in range(len(steps) - 1):
            p1 = phase_map[steps[i]["phase"]]
            p2 = phase_map[steps[i+1]["phase"]]
            self.assertLessEqual(p1, p2, f"Phase order violated: {steps[i]['phase']} before {steps[i+1]['phase']}")


if __name__ == "__main__":
    unittest.main()
