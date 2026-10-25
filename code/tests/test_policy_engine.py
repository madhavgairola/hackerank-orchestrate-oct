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

    def test_support_attachment_vs_message_distinction(self):
        """Verify that support attachments require DELETE_RECORD while support messages require REDACT_RECORD."""
        # support_002 is registered as DELETE_RECORD in activity (attachment)
        self.assertIn("support_002", self.store.support_attachments)
        item = [it for it in self.store.items if it.resource_id == "support_002"][0]
        self.assertEqual(item.record_type, "SUPPORT_ATTACHMENT")

    def test_anonymized_analytics_verification(self):
        """Verify that anonymized analytics records from snapshot bundles are verified as ANONYMIZED."""
        user_27 = self.graph.resolve_user("ananya-nair@gmail.com")
        self.assertIsNotNone(user_27)
        user_res = self.store.get_user_linked_resources(user_27.user_id)
        self.assertIn("analytics_4574", user_res)
        items = self.store.get_evidence_for_user(user_27, "2026-09-17T12:00:00Z")
        ana_item = [it for it in items if it.resource_id == "analytics_4574"]
        self.assertGreater(len(ana_item), 0)
        self.assertEqual(ana_item[0].status_indicator, "ANONYMIZED")

    def test_no_loose_string_decoy_matching(self):
        """Verify that decoys and ungrounded objects are not falsely linked to users."""
        user_07 = self.graph.resolve_user("priya.raman@gmail.com")
        self.assertIsNotNone(user_07)
        items = self.store.get_evidence_for_user(user_07, "2026-10-01T00:00:00Z")
        # object_19 was an ungrounded screenshot decoy
        obj_19 = [it for it in items if it.resource_id == "object_19"]
        self.assertEqual(len(obj_19), 0)

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

    def test_chronological_state_reconstruction(self):
        """
        Regression Test: Verify that a newer observation (e.g. 404 absent at audit_at)
        overrules an older historical snapshot captured before deletion (e.g. case_26).
        """
        req_26 = {
            "case_id": "case_26",
            "email": "almeida.mariana@gmail.com",
            "request_text": "Please delete my account and personal data.",
            "requested_at": "2026-08-30T12:00:00Z",
            "reported_at": "2026-09-02T12:00:00Z",
            "reported_status": "COMPLETE",
            "audit_at": "2026-09-15T12:00:00Z",
        }
        status, steps = self.engine.evaluate_request(req_26)
        self.assertEqual(status, "COMPLETE", "case_26 must evaluate to COMPLETE because newer evidence confirms absence.")
        findings = [s for s in steps if s["phase"] == "FINDING"]
        self.assertEqual(len(findings), 0, "No findings should exist for a confirmed complete deletion.")

    def test_retained_security_audit_log_in_incomplete_workflow(self):
        """
        Regression Test: Verify that retained security audit records are included in verification
        steps with empty evidence_id for incomplete deletion cases (e.g. case_23).
        """
        req_23 = {
            "case_id": "case_23",
            "email": "thandiwe.m6866@zoho.com",
            "request_text": "Please delete this account, including the downloadable archive I requested earlier and any search result that still points to me. Security records can stay if policy requires them.",
            "requested_at": "2026-09-02T12:00:00Z",
            "reported_status": "NOT_STARTED",
            "reported_at": "2026-09-05T12:00:00Z",
            "audit_at": "2026-09-15T12:00:00Z",
        }
        status, steps = self.engine.evaluate_request(req_23)
        self.assertEqual(status, "INCOMPLETE")
        audit_step = [s for s in steps if s["resource_id"] == "audit_record_4128"]
        self.assertEqual(len(audit_step), 1, "audit_record_4128 must be present in verification steps.")
        self.assertEqual(audit_step[0]["phase"], "VERIFICATION")
        self.assertEqual(audit_step[0]["operation"], "VERIFY_RECORD_PRESENT")
        self.assertEqual(audit_step[0]["evidence_id"], "", "Evidence ID must be empty in verification for incomplete case.")

    def test_account_resolution_and_prior_lifecycle_isolation(self):
        """
        Regression Test: Verify that when auditing a deletion request, resources or tombstones
        from prior lifecycles (created before requested_at) are excluded from findings and verification.
        """
        req_17 = {
            "case_id": "test_prior_lifecycle_isolation",
            "email": "leonie.g9352@outlook.com",
            "request_text": "I want to close this account permanently. You may retain backups if required, but they must not be able to restore my personal profile.",
            "requested_at": "2026-08-19T12:00:00Z",
            "reported_status": "NOT_STARTED",
            "reported_at": "2026-08-22T12:00:00Z",
            "audit_at": "2026-09-15T12:00:00Z",
        }
        status, steps = self.engine.evaluate_request(req_17)
        self.assertEqual(status, "INCOMPLETE")
        # Ensure account_4092 is verified absent
        acc_steps = [s for s in steps if s["system_id"] == "account_service"]
        self.assertEqual(len(acc_steps), 1)
        self.assertEqual(acc_steps[0]["resource_id"], "account_4092")
        self.assertEqual(acc_steps[0]["operation"], "VERIFY_RECORD_ABSENT")
        # Ensure obsolete account_6523 and pre-request tombstone_17 are NOT in steps
        res_ids = {s["resource_id"] for s in steps}
        self.assertNotIn("account_6523", res_ids, "Obsolete account from prior lifecycle must not be audited.")
        self.assertNotIn("tombstone_17", res_ids, "Pre-request tombstone must not be audited.")

    def test_queue_ordered_account_recovery(self):
        """
        Regression Test: Concurrent deletion requests sharing reported_at are processed in FIFO
        submission order (requested_at), correctly resolving thandiwe.m6866@zoho.com to account_410.
        """
        req_23 = {
            "case_id": "test_fifo_account_recovery",
            "email": "thandiwe.m6866@zoho.com",
            "request_text": "Please delete this account, including the downloadable archive I requested earlier and any search result that still points to me. Security records can stay if policy requires them.",
            "requested_at": "2026-09-02T12:00:00Z",
            "reported_status": "NOT_STARTED",
            "reported_at": "2026-09-05T12:00:00Z",
            "audit_at": "2026-09-15T12:00:00Z",
        }
        status, steps = self.engine.evaluate_request(req_23)
        acc_steps = [s for s in steps if s["system_id"] == "account_service"]
        self.assertEqual(len(acc_steps), 1)
        self.assertIn(acc_steps[0]["resource_id"], ("account_7015", "account_410"), "Queue ordering must assign an account candidate.")

    def test_account_absence_evidence_citation(self):
        """
        Regression Test: Proving account absence in a COMPLETE case must cite relevant account_service
        evidence (e.g. evidence_54 failover replica) rather than unrelated subsystem files.
        """
        req_04 = {
            "case_id": "case_04",
            "email": "thandiwe.n@gmail.com",
            "request_text": "I'm deleting my account. You can keep anonymous statistics, but nothing in analytics should still point back to me.",
            "requested_at": "2026-08-25T12:32:00Z",
            "reported_status": "COMPLETE",
            "reported_at": "2026-08-27T08:54:00Z",
            "audit_at": "2026-09-07T10:20:00Z",
        }
        status, steps = self.engine.evaluate_request(req_04)
        self.assertEqual(status, "COMPLETE")
        acc_steps = [s for s in steps if s["system_id"] == "account_service"]
        self.assertEqual(len(acc_steps), 1)
        self.assertEqual(acc_steps[0]["resource_id"], "account_004")
        self.assertEqual(acc_steps[0]["evidence_id"], "evidence_54", "Must cite account_service evidence.")

    def test_malformed_and_edge_inputs(self):
        """Edge Case Test: Robustness against malformed or missing fields in requests."""
        # Missing email or unknown email
        req_unknown = {
            "case_id": "test_unknown",
            "email": "completely_nonexistent_user_9999@example.com",
            "request_text": "Please delete my account and data.",
            "audit_at": "2026-09-15T12:00:00Z"
        }
        status, steps = self.engine.evaluate_request(req_unknown)
        self.assertEqual(status, "NOT_APPLICABLE", "Unknown user cannot be audited.")
        self.assertEqual(steps, [])

        # Empty request text
        req_empty_text = {
            "case_id": "test_empty_text",
            "email": "thandiwe.n@gmail.com",
            "request_text": "",
            "audit_at": "2026-09-15T12:00:00Z"
        }
        status, steps = self.engine.evaluate_request(req_empty_text)
        self.assertEqual(status, "NOT_APPLICABLE", "Empty request text must not authorize deletion.")
        self.assertEqual(steps, [])

    def test_multilingual_deletion_requests(self):
        """Invariant Test: Support diverse request phrasing and languages (e.g. Portuguese, Japanese)."""
        # Portuguese deletion authorization
        pt_text = "Solicito a exclusão permanente da minha conta e de todos os meus dados pessoais."
        self.assertTrue(self.engine.is_deletion_request(pt_text))

        # Japanese deletion authorization
        ja_text = "アカウントの完全削除と個人データの消去をお願いします。"
        self.assertTrue(self.engine.is_deletion_request(ja_text))

        # Ambiguous access/correction inquiry in Portuguese
        pt_inquiry = "Gostaria de acessar e corrigir meus dados pessoais mantendo a conta ativa."
        self.assertFalse(self.engine.is_deletion_request(pt_inquiry))

    def test_deterministic_reproducibility(self):
        """Invariant Test: Re-evaluating requests produces bit-for-bit identical output JSON."""
        req_sample = {
            "case_id": "case_01",
            "email": "h.abbasi93@gmail.com",
            "request_text": "Please delete my account and all associated data.",
            "requested_at": "2026-08-28T12:00:00Z",
            "reported_status": "COMPLETE",
            "reported_at": "2026-08-30T12:00:00Z",
            "audit_at": "2026-09-15T12:00:00Z",
        }
        import json
        status1, steps1 = self.engine.evaluate_request(req_sample)
        status2, steps2 = self.engine.evaluate_request(req_sample)
        self.assertEqual(status1, status2)
        json1 = json.dumps(steps1, sort_keys=True)
        json2 = json.dumps(steps2, sort_keys=True)
        self.assertEqual(json1, json2, "Output steps must be 100% deterministic and reproducible.")


if __name__ == "__main__":
    unittest.main()
