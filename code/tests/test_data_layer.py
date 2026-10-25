"""
Test suite for Identity Resolution and Evidence Store Data Layer.
Tests:
1. Historical email matching from user_audit_log.csv
2. Case-insensitive email and hash matching
3. Indirect resource linkage (via system_activity.csv and catalog links)
4. Mixed evidence formats (SQL, JSON, LOG, TXT, PDF, Screenshot models)
5. Audit-time cutoff filtering (captured_at <= audit_at)
"""

import os
import sys
import unittest

# Ensure code directory is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from identity import IdentityGraph, UserIdentity, normalize_email
from evidence_store import EvidenceStore, EvidenceItem


class TestDataLayer(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        cls.dataset_dir = os.path.join(cls.repo_root, "dataset")
        cls.identities_csv = os.path.join(cls.dataset_dir, "user_identities.csv")
        cls.audit_csv = os.path.join(cls.dataset_dir, "user_audit_log.csv")

        cls.graph = IdentityGraph(cls.identities_csv, cls.audit_csv)
        cls.store = EvidenceStore(cls.dataset_dir, cls.graph)

    def test_case_insensitive_matching(self):
        """Verify that uppercase, mixed-case, and lowercase emails resolve to the exact same UserIdentity."""
        # user_11: haruka.s1838@zoho.com
        user_lower = self.graph.resolve_user("haruka.s1838@zoho.com")
        user_upper = self.graph.resolve_user("HARUKA.S1838@ZOHO.COM")
        user_mixed = self.graph.resolve_user("HaRuKa.S1838@ZoHo.CoM")

        self.assertIsNotNone(user_lower)
        self.assertIsNotNone(user_upper)
        self.assertIsNotNone(user_mixed)
        self.assertEqual(user_lower.user_id, "user_11")
        self.assertEqual(user_upper.user_id, "user_11")
        self.assertEqual(user_mixed.user_id, "user_11")

    def test_historical_email_matching(self):
        """Verify that an old email recorded in user_audit_log resolves to the user even if updated."""
        # user_10: nadia.ionescu@yahoo.com was changed to nadia.petrescu@yahoo.com (audit_121)
        user_by_old = self.graph.resolve_user("nadia.ionescu@yahoo.com")
        user_by_new = self.graph.resolve_user("nadia.petrescu@yahoo.com")

        self.assertIsNotNone(user_by_old)
        self.assertIsNotNone(user_by_new)
        self.assertEqual(user_by_old.user_id, "user_10")
        self.assertEqual(user_by_new.user_id, "user_10")
        # Ensure user object contains both emails
        self.assertIn("nadia.ionescu@yahoo.com", user_by_old.emails)
        self.assertIn("nadia.petrescu@yahoo.com", user_by_old.emails)

    def test_indirect_resource_linkage(self):
        """Verify that secondary resources (e.g. data flows, backups, exports) linked via activity are found."""
        # user_14: data_flow_1121 linked via LINK_RESOURCE_IDENTITY (activity_4002)
        user_14 = self.graph.resolve_user("jain.aditi@gmail.com")
        self.assertIsNotNone(user_14)
        linked_resources = self.store.get_user_linked_resources(user_14.user_id)
        self.assertIn("data_flow_1121", linked_resources)

        # user_16: backup_9287 linked via activity_4006
        user_16 = self.graph.resolve_user("areed1433@gmail.com")
        self.assertIsNotNone(user_16)
        linked_16 = self.store.get_user_linked_resources(user_16.user_id)
        self.assertIn("backup_9287", linked_16)

    def test_mixed_evidence_formats(self):
        """Verify that evidence items are successfully extracted across SQL, JSON, LOG, TXT, PDF, and screenshots."""
        systems_found = set()
        formats_found = set()
        total_items = len(self.store.items)

        self.assertGreater(total_items, 100, "Store should contain hundreds of normalized evidence records.")

        for item in self.store.items:
            systems_found.add(item.system_id)
            fid = item.evidence_id
            meta = self.store.manifest.get(fid, {})
            fp = meta.get("file_path", "")
            ext = os.path.splitext(fp)[1]
            if ext:
                formats_found.add(ext)

        # Check coverage of key systems
        required_systems = {
            "account_service",
            "search_service",
            "analytics_platform",
            "support_platform",
            "export_service",
            "integration_service",
            "backup_service",
            "security_service",
            "identity_service",
        }
        for s in required_systems:
            self.assertIn(s, systems_found, f"System {s} was not found in parsed evidence.")

        # Check coverage of key formats
        required_formats = {".sql", ".json", ".log", ".txt", ".pdf", ".png"}
        for f in required_formats:
            self.assertIn(f, formats_found, f"Format {f} was not found in parsed evidence manifest.")

    def test_audit_cutoff_filtering(self):
        """Verify that get_evidence_for_user strictly rejects evidence captured after audit_at."""
        user = self.graph.resolve_user("amina.elmasri@gmail.com")
        self.assertIsNotNone(user)

        # Early cutoff: before evidence_54 (captured 2026-09-02T23:00:00Z)
        early_cutoff = "2026-09-01T00:00:00Z"
        items_early = self.store.get_evidence_for_user(user, early_cutoff)
        for it in items_early:
            self.assertLessEqual(it.captured_at, early_cutoff)

        # Later cutoff: after evidence_54
        late_cutoff = "2026-09-05T00:00:00Z"
        items_late = self.store.get_evidence_for_user(user, late_cutoff)
        for it in items_late:
            self.assertLessEqual(it.captured_at, late_cutoff)

        # Ensure future items are never returned
        self.assertTrue(len(items_late) >= len(items_early))

    def test_generalization_coverage(self):
        """Verify that every user in user_identities is accessible and indexed."""
        all_users = self.graph.all_users()
        self.assertEqual(len(all_users), 850)
        # Verify arbitrary user
        u = self.graph.get_user("user_500")
        self.assertIsNotNone(u)
        self.assertTrue(len(u.emails) >= 1)

    def test_deleted_account_state_and_evidence(self):
        """
        Regression Test 1: For already-deleted accounts, verify recovery from activity/traces
        and determination of empirical state from evidence at audit_at without trusting workflow claims alone.
        """
        # User 43 (l.fontaine46@yahoo.com): account_7566 deleted
        user_43 = self.graph.resolve_user("l.fontaine46@yahoo.com")
        self.assertIsNotNone(user_43)

        audit_at_43 = "2026-09-26T11:00:00Z"
        items_43 = self.store.get_evidence_for_user(user_43, audit_at_43)
        acct_items_43 = [it for it in items_43 if it.system_id == "account_service" and it.resource_id == "account_7566"]
        self.assertGreater(len(acct_items_43), 0, "Account account_7566 should be recovered from lookup trace evidence.")

        # Confirm readback evidence (evidence_94) demonstrates ABSENT (404) at audit_at
        absent_evidence = [it for it in acct_items_43 if it.status_indicator == "ABSENT"]
        self.assertGreater(len(absent_evidence), 0, "Should have empirical evidence proving account is ABSENT.")
        self.assertEqual(absent_evidence[0].evidence_id, "evidence_94")

        # Contrast with User 05 (leila.haddad@yahoo.com): account_005 reported complete by deletion_worker
        # but failover replica snapshot (evidence_54) captured before audit_at proves account_005 is still PRESENT
        user_05 = self.graph.resolve_user("leila.haddad@yahoo.com")
        self.assertIsNotNone(user_05)
        audit_at_05 = "2026-09-02T23:00:00Z"
        items_05 = self.store.get_evidence_for_user(user_05, audit_at_05)
        acct_present_05 = [it for it in items_05 if it.resource_id == "account_005" and it.status_indicator == "PRESENT"]
        self.assertGreater(len(acct_present_05), 0, "Replica snapshot evidence must prove account_005 remains PRESENT.")
        self.assertEqual(acct_present_05[0].evidence_id, "evidence_54")

    def test_anonymized_analytics_association_and_state(self):
        """
        Regression Test 2: For analytics records, verify association via activity/timeline
        and verification of whether identifiers were actually removed at audit_at.
        """
        # User 29 (noah.f438085@outlook.com): analytics_5208 claimed anonymized by workflow,
        # but snapshot evidence (evidence_92) captured at audit_at still contains email and user_id -> PRESENT (Exposed PII)
        user_29 = self.graph.resolve_user("noah.f438085@outlook.com")
        self.assertIsNotNone(user_29)
        audit_at_29 = "2026-09-17T12:00:00Z"
        items_29 = self.store.get_evidence_for_user(user_29, audit_at_29)
        analytics_29 = [it for it in items_29 if it.system_id == "analytics_platform" and it.resource_id == "analytics_5208"]
        self.assertGreater(len(analytics_29), 0, "analytics_5208 should be linked to user_29.")
        exposed_items = [it for it in analytics_29 if it.status_indicator == "PRESENT" and it.email is not None]
        self.assertGreater(len(exposed_items), 0, "analytics_5208 should be proven PRESENT with exposed email in snapshot.")

        # User 04 (thandiwe.n@gmail.com): analytics_901 is associated through trace/evidence
        user_04 = self.graph.resolve_user("thandiwe.n@gmail.com")
        linked_04 = self.store.get_user_linked_resources(user_04.user_id)
        self.assertIn("analytics_901", linked_04, "analytics_901 should be associated with user_04.")

    def test_sql_record_json_parsing(self):
        """
        Regression Test 3 (Issue 1): Verify SQL snapshots with record_json (e.g. evidence_05)
        parse payloads, extract origin_system, and link identifiers properly.
        """
        user_53 = self.graph.resolve_user("diya.k4436@outlook.com")
        self.assertIsNotNone(user_53)
        items = self.store.get_evidence_for_user(user_53, "2026-09-21T10:00:00Z")
        ev05_items = [it for it in items if it.evidence_id == "evidence_05"]
        self.assertGreater(len(ev05_items), 0, "evidence_05 records inside record_json must be unpacked.")

        # Check account_994 is mapped to account_service and marked PRESENT
        acc_994 = [it for it in ev05_items if it.resource_id == "account_994"]
        self.assertEqual(len(acc_994), 1)
        self.assertEqual(acc_994[0].system_id, "account_service")
        self.assertEqual(acc_994[0].status_indicator, "PRESENT")

        # Check search_1007 is mapped to search_service
        search_1007 = [it for it in ev05_items if it.resource_id == "search_1007"]
        self.assertGreaterEqual(len(search_1007), 1)
        self.assertEqual(search_1007[0].system_id, "search_service")

    def test_deletion_worker_account_recovery(self):
        """
        Regression Test 4 (Issue 2): Recover account resource IDs from actual deletion-worker
        activity chains instead of inferring account IDs from user IDs.
        """
        # User 541 (case_31): account_4857 (not account_541)
        user_541 = self.graph.resolve_user("a.eze08@gmail.com")
        self.assertIsNotNone(user_541)
        req_31 = {
            "reported_at": "2026-09-06T12:00:00Z",
            "reported_status": "COMPLETE",
            "requested_at": "2026-09-04T12:00:00Z",
        }
        acc_31 = self.store.get_or_recover_account_id(user_541, req_31)
        self.assertEqual(acc_31, "account_4857", "Account ID must be recovered from deletion worker chain.")

        # User 542 (case_32): account_8858 (not account_542)
        user_542 = self.graph.resolve_user("addo.kofi@gmail.com")
        self.assertIsNotNone(user_542)
        req_32 = {
            "reported_at": "2026-09-06T12:00:00Z",
            "reported_status": "PARTIALLY_COMPLETE",
            "requested_at": "2026-09-03T12:00:00Z",
        }
        acc_32 = self.store.get_or_recover_account_id(user_542, req_32)
        self.assertEqual(acc_32, "account_8858", "Account ID must be recovered from deletion worker chain.")

    def test_tightened_activity_correlation(self):
        """
        Regression Test 5 (Issue 3): Verify concurrent deletion jobs do not pull in decoy resources
        belonging to other users without supporting identity or trace evidence.
        """
        # User 32 (case_11: novak.tomasz@icloud.com): shares 2026-09-12 timestamp with other batches.
        # Must only contain user_32's own resources, not foreign search or support records.
        user_32 = self.graph.resolve_user("novak.tomasz@icloud.com")
        self.assertIsNotNone(user_32)
        linked = self.store.get_user_linked_resources(user_32.user_id)
        # Confirm decoys from other users running on 2026-09-12 are NOT linked
        self.assertNotIn("search_8911", linked)
        self.assertNotIn("support_4707", linked)
        self.assertNotIn("backup_3870", linked)


if __name__ == "__main__":
    unittest.main()
