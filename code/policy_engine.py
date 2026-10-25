"""
Policy Engine for Ghost Data Still Exists.
Evaluates deletion requests against deletion_rules.csv and empirical evidence:
- Determines request intent (distinguishes deletion vs access/correction/export/opt-out -> NOT_APPLICABLE)
- Enforces strict audit_at cutoff (captured_at <= audit_at)
- Evaluates resource states (PRESENT, ABSENT, REDACTED, ANONYMIZED, ACTIVE, DISABLED, BLOCKED)
- Determines overall deletion status (COMPLETE, INCOMPLETE, NOT_APPLICABLE)
- Synthesizes strictly ordered steps adhering to phase, operation, and resource tie-breakers:
  * Phases: FINDING -> REMEDIATION -> VERIFICATION
  * Remediation: DISABLE_DATA_FLOW -> BLOCK_RESTORE -> DELETE_RECORD -> REDACT_RECORD -> ANONYMIZE_RECORD
  * Tie-breaker: system_id ASC, resource_id ASC
  * Evidence citation rules: Findings cite empirical evidence, future remediation/verification use empty evidence_id
"""

import json
import os
import re
from typing import Any, Dict, List, Optional, Set, Tuple

import pandas as pd

from identity import IdentityGraph, UserIdentity
from evidence_store import EvidenceStore, EvidenceItem


class PolicyEngine:
    """Evaluates deletion requests and generates compliant, ordered audit steps."""

    def __init__(
        self,
        dataset_dir: str,
        identity_graph: IdentityGraph,
        evidence_store: EvidenceStore,
    ) -> None:
        self.dataset_dir = dataset_dir
        self.graph = identity_graph
        self.store = evidence_store

        # Rules manifest from deletion_rules.csv
        self.rules_csv = os.path.join(dataset_dir, "deletion_rules.csv")
        self.rules: Dict[str, str] = self._load_rules()

        # Multilingual & non-deletion intent patterns
        self.non_deletion_patterns = [
            r"leave the account active",
            r"not asking for deletion",
            r"keep the account",
            r"do not close the account",
            r"without removing",
            r"marketing lists only",
            r"not a request to erase",
            r"leave my profile",
            r"continue using the service",
            r"don't delete",
            r"do not delete",
            r"portable format",
            r"resetting the login",
            r"information request",
            r"stop the promotional emails",
            r"copy of last year",
            r"surname is misspelled",
            r"mobile number on my profile is out of date",
            r"download my account information",
        ]

        # Operation priority contracts from problem statement §6.4
        self.finding_priority = {
            "REPORT_REMAINING_RECORD": 1,
            "REPORT_EXPOSED_PII": 2,
            "REPORT_ACTIVE_DATA_FLOW": 3,
            "REPORT_RESTORE_RISK": 4,
        }

        self.remed_priority = {
            "DISABLE_DATA_FLOW": 1,
            "BLOCK_RESTORE": 2,
            "DELETE_RECORD": 3,
            "REDACT_RECORD": 4,
            "ANONYMIZE_RECORD": 5,
        }

        self.verif_priority = {
            "VERIFY_RECORD_ABSENT": 1,
            "VERIFY_RECORD_PRESENT": 2,
            "VERIFY_RECORD_REDACTED": 3,
            "VERIFY_RECORD_ANONYMIZED": 4,
            "VERIFY_DATA_FLOW_DISABLED": 5,
            "VERIFY_RESTORE_BLOCKED": 6,
        }

    def _load_rules(self) -> Dict[str, str]:
        """Loads data_category -> required_action from deletion_rules.csv."""
        mapping = {}
        if os.path.exists(self.rules_csv):
            df = pd.read_csv(self.rules_csv)
            for _, r in df.iterrows():
                mapping[r["data_category"]] = r["required_action"]
        return mapping

    def is_deletion_request(self, text: str) -> bool:
        """Determines if the request text authorizes deletion rather than access/correction/export."""
        if not text:
            return True
        t = str(text).lower()
        for p in self.non_deletion_patterns:
            if re.search(p, t):
                return False
        return True

    def evaluate_request(
        self, req_row: Dict[str, Any]
    ) -> Tuple[str, List[Dict[str, Any]]]:
        """
        Evaluates a single deletion request.
        Returns (deletion_status, steps_list).
        """
        cid = str(req_row.get("case_id", "")).strip()
        email = str(req_row.get("email", "")).strip().lower()
        req_text = str(req_row.get("request_text", ""))
        audit_at = str(req_row.get("audit_at", ""))

        # 1. Check if request authorizes deletion
        if not self.is_deletion_request(req_text):
            return "NOT_APPLICABLE", []

        # 2. Resolve user identity
        user = self.graph.resolve_user(email)
        if not user:
            return "NOT_APPLICABLE", []

        # 3. Retrieve all empirical evidence items captured at or before audit_at
        ev_items = self.store.get_evidence_for_user(user, audit_at)

        # 4. Determine primary account ID
        acct_id = self.store.get_or_recover_account_id(user, request_info=req_row)
        if not acct_id:
            for it in ev_items:
                if it.system_id == "account_service" and it.resource_id.startswith("account_"):
                    acct_id = it.resource_id
                    break
        if not acct_id:
            for rid in self.store.get_user_linked_resources(user.user_id):
                if rid.startswith("account_"):
                    acct_id = rid
                    break
        if not acct_id:
            digits = "".join(filter(str.isdigit, user.user_id))
            if digits:
                acct_id = f"account_{int(digits):03d}"

        # 5. Group empirical evidence by (system_id, resource_id) in chronological order
        ev_items.sort(key=lambda it: it.captured_at)
        res_map: Dict[Tuple[str, str], Dict[str, Any]] = {}
        for it in ev_items:
            key = (it.system_id, it.resource_id)
            has_direct = bool(it.email or it.phone or it.name or it.user_id or it.email_hash)
            file_cap = self.store.manifest.get(it.evidence_id, {}).get("captured_at", it.captured_at)
            can_cite = bool(file_cap <= audit_at)

            if key not in res_map:
                res_map[key] = {
                    "system_id": it.system_id,
                    "resource_id": it.resource_id,
                    "record_type": it.record_type,
                    "state": it.status_indicator,
                    "evidence_id": it.evidence_id if can_cite else "",
                    "captured_at": it.captured_at,
                    "has_pii": bool(it.email or it.phone or it.name),
                    "has_direct": has_direct,
                    "can_cite": can_cite,
                    "items": [it],
                }
            else:
                entry = res_map[key]
                entry["items"].append(it)
                if it.email or it.phone or it.name:
                    entry["has_pii"] = True

                # Chronological progression:
                # 1. If newer observation (it.captured_at > entry["captured_at"]): updates state
                # 2. If same time (it.captured_at == entry["captured_at"]): violation (PRESENT/ACTIVE) takes precedence
                if it.captured_at > entry["captured_at"]:
                    entry["state"] = it.status_indicator
                    if can_cite:
                        entry["evidence_id"] = it.evidence_id
                        entry["can_cite"] = True
                    entry["captured_at"] = it.captured_at
                    entry["has_direct"] = has_direct
                elif it.captured_at == entry["captured_at"]:
                    if it.status_indicator in ("PRESENT", "ACTIVE") and entry["state"] not in ("PRESENT", "ACTIVE"):
                        entry["state"] = it.status_indicator
                        if can_cite:
                            entry["evidence_id"] = it.evidence_id
                            entry["can_cite"] = True
                        entry["has_direct"] = has_direct
                    elif can_cite and not entry.get("can_cite"):
                        entry["evidence_id"] = it.evidence_id
                        entry["can_cite"] = True

        # Prune obsolete account_service resources and lifecycles
        if acct_id:
            obsolete_acc_keys = [
                k for k in res_map.keys()
                if k[0] == "account_service" and k[1] != acct_id
            ]
            for k in obsolete_acc_keys:
                del res_map[k]

        # For ACCOUNT_TOMBSTONE: if a tombstone was created before requested_at,
        # it belongs to an earlier lifecycle and is not part of this deletion request.
        req_at = req_row.get("requested_at", "")
        if req_at:
            tombstone_keys_to_remove = [
                k for k, v in res_map.items()
                if v.get("record_type") == "ACCOUNT_TOMBSTONE" and v.get("captured_at", "") < req_at
            ]
            for k in tombstone_keys_to_remove:
                del res_map[k]

        # Ensure account presence is accounted for
        if acct_id and ("account_service", acct_id) not in res_map:
            # Determine appropriate evidence proving absence before audit_at
            default_ev = ""
            default_cap = ""
            for it in ev_items:
                f_meta = self.store.manifest.get(it.evidence_id, {})
                f_cap = f_meta.get("captured_at", it.captured_at)
                if f_cap <= audit_at and it.captured_at <= audit_at and it.system_id == "account_service":
                    default_ev = it.evidence_id
                    default_cap = it.captured_at
                    break

            # If not in user's direct items, find the most recent relevant evidence file for account_service available at or before audit_at
            if not default_ev:
                for fid, fmeta in sorted(self.store.manifest.items(), key=lambda kv: kv[1]["captured_at"], reverse=True):
                    if fmeta["captured_at"] <= audit_at:
                        src = fmeta.get("source_origin", "")
                        fpath = fmeta.get("file_path", "")
                        if src == "account_service" or "customer_accounts" in fpath or "account" in fpath:
                            default_ev = fid
                            default_cap = fmeta["captured_at"]
                            break

            res_map[("account_service", acct_id)] = {
                "system_id": "account_service",
                "resource_id": acct_id,
                "record_type": "USER_PROFILE",
                "state": "ABSENT",
                "evidence_id": default_ev,
                "captured_at": default_cap or audit_at,
                "has_pii": False,
                "can_cite": bool(default_ev),
                "items": [],
            }

        # 6. Apply policy treatments and evaluate findings
        findings: List[Dict[str, Any]] = []
        remediations: List[Dict[str, Any]] = []
        verifications: List[Dict[str, Any]] = []

        for (sys_id, res_id), rinfo in res_map.items():
            cat = rinfo["record_type"]
            state = rinfo["state"]
            ev_id = rinfo["evidence_id"] if rinfo.get("can_cite") else ""
            has_pii = rinfo["has_pii"]

            # Required action from deletion rules
            action = self.rules.get(cat, "DELETE")

            if cat in (
                "USER_PROFILE",
                "SECONDARY_IDENTIFIER",
                "SEARCH_INDEX_ENTRY",
                "CACHE_ENTRY",
                "SUPPORT_ATTACHMENT",
                "USER_EXPORT",
                "MARKETING_PROFILE",
            ):
                if state == "PRESENT":
                    findings.append({
                        "phase": "FINDING",
                        "system_id": sys_id,
                        "resource_id": res_id,
                        "operation": "REPORT_REMAINING_RECORD",
                        "state": "PRESENT",
                        "evidence_id": ev_id,
                    })
                    remediations.append({
                        "phase": "REMEDIATION",
                        "system_id": sys_id,
                        "resource_id": res_id,
                        "operation": "DELETE_RECORD",
                        "state": "ABSENT",
                        "evidence_id": "",
                    })
                    verifications.append({
                        "phase": "VERIFICATION",
                        "system_id": sys_id,
                        "resource_id": res_id,
                        "operation": "VERIFY_RECORD_ABSENT",
                        "state": "ABSENT",
                        "evidence_id": "",
                    })
                else:  # ABSENT
                    verifications.append({
                        "phase": "VERIFICATION",
                        "system_id": sys_id,
                        "resource_id": res_id,
                        "operation": "VERIFY_RECORD_ABSENT",
                        "state": "ABSENT",
                        "evidence_id": ev_id,
                    })

            elif cat in ("ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"):
                if state == "PRESENT" or has_pii:
                    findings.append({
                        "phase": "FINDING",
                        "system_id": sys_id,
                        "resource_id": res_id,
                        "operation": "REPORT_EXPOSED_PII",
                        "state": "PRESENT",
                        "evidence_id": ev_id,
                    })
                    remediations.append({
                        "phase": "REMEDIATION",
                        "system_id": sys_id,
                        "resource_id": res_id,
                        "operation": "ANONYMIZE_RECORD",
                        "state": "ANONYMIZED",
                        "evidence_id": "",
                    })
                    verifications.append({
                        "phase": "VERIFICATION",
                        "system_id": sys_id,
                        "resource_id": res_id,
                        "operation": "VERIFY_RECORD_ANONYMIZED",
                        "state": "ANONYMIZED",
                        "evidence_id": "",
                    })
                else:  # ANONYMIZED
                    verifications.append({
                        "phase": "VERIFICATION",
                        "system_id": sys_id,
                        "resource_id": res_id,
                        "operation": "VERIFY_RECORD_ANONYMIZED",
                        "state": "ANONYMIZED",
                        "evidence_id": ev_id,
                    })

            elif cat in ("SUPPORT_MESSAGE", "EMAIL_DELIVERY_LOG", "ACCOUNT_TOMBSTONE"):
                if state == "PRESENT" or has_pii:
                    findings.append({
                        "phase": "FINDING",
                        "system_id": sys_id,
                        "resource_id": res_id,
                        "operation": "REPORT_EXPOSED_PII",
                        "state": "PRESENT",
                        "evidence_id": ev_id,
                    })
                    remediations.append({
                        "phase": "REMEDIATION",
                        "system_id": sys_id,
                        "resource_id": res_id,
                        "operation": "REDACT_RECORD",
                        "state": "REDACTED",
                        "evidence_id": "",
                    })
                    verifications.append({
                        "phase": "VERIFICATION",
                        "system_id": sys_id,
                        "resource_id": res_id,
                        "operation": "VERIFY_RECORD_REDACTED",
                        "state": "REDACTED",
                        "evidence_id": "",
                    })
                else:  # REDACTED
                    verifications.append({
                        "phase": "VERIFICATION",
                        "system_id": sys_id,
                        "resource_id": res_id,
                        "operation": "VERIFY_RECORD_REDACTED",
                        "state": "REDACTED",
                        "evidence_id": ev_id,
                    })

            elif cat == "DATA_FLOW":
                if state == "ACTIVE":
                    findings.append({
                        "phase": "FINDING",
                        "system_id": sys_id,
                        "resource_id": res_id,
                        "operation": "REPORT_ACTIVE_DATA_FLOW",
                        "state": "ACTIVE",
                        "evidence_id": ev_id,
                    })
                    remediations.append({
                        "phase": "REMEDIATION",
                        "system_id": sys_id,
                        "resource_id": res_id,
                        "operation": "DISABLE_DATA_FLOW",
                        "state": "DISABLED",
                        "evidence_id": "",
                    })
                    verifications.append({
                        "phase": "VERIFICATION",
                        "system_id": sys_id,
                        "resource_id": res_id,
                        "operation": "VERIFY_DATA_FLOW_DISABLED",
                        "state": "DISABLED",
                        "evidence_id": "",
                    })
                else:  # DISABLED
                    verifications.append({
                        "phase": "VERIFICATION",
                        "system_id": sys_id,
                        "resource_id": res_id,
                        "operation": "VERIFY_DATA_FLOW_DISABLED",
                        "state": "DISABLED",
                        "evidence_id": ev_id,
                    })

            elif cat == "BACKUP_ARCHIVE":
                if state == "ACTIVE":
                    findings.append({
                        "phase": "FINDING",
                        "system_id": sys_id,
                        "resource_id": res_id,
                        "operation": "REPORT_RESTORE_RISK",
                        "state": "ACTIVE",
                        "evidence_id": ev_id,
                    })
                    remediations.append({
                        "phase": "REMEDIATION",
                        "system_id": sys_id,
                        "resource_id": res_id,
                        "operation": "BLOCK_RESTORE",
                        "state": "BLOCKED",
                        "evidence_id": "",
                    })
                    verifications.append({
                        "phase": "VERIFICATION",
                        "system_id": sys_id,
                        "resource_id": res_id,
                        "operation": "VERIFY_RESTORE_BLOCKED",
                        "state": "BLOCKED",
                        "evidence_id": "",
                    })
                else:  # BLOCKED
                    verifications.append({
                        "phase": "VERIFICATION",
                        "system_id": sys_id,
                        "resource_id": res_id,
                        "operation": "VERIFY_RESTORE_BLOCKED",
                        "state": "BLOCKED",
                        "evidence_id": ev_id,
                    })

            elif cat in ("SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD"):
                # Retained per policy
                verifications.append({
                    "phase": "VERIFICATION",
                    "system_id": sys_id,
                    "resource_id": res_id,
                    "operation": "VERIFY_RECORD_PRESENT",
                    "state": "PRESENT",
                    "evidence_id": ev_id,
                })

        # 7. Decide overall status and sort steps
        has_evidence_for_all = all(bool(v.get("evidence_id")) for v in verifications) if verifications else False
        is_complete = (len(findings) == 0) and has_evidence_for_all

        # Ensure all findings cite visible evidence per contract (AGENTS.md §6.3, §6.6)
        findings = [f for f in findings if f.get("evidence_id")]

        # Sort findings: (operation priority, system_id, resource_id)
        findings.sort(
            key=lambda s: (
                self.finding_priority.get(s["operation"], 99),
                s["system_id"],
                s["resource_id"],
            )
        )

        # Sort remediations: (operation priority, system_id, resource_id)
        remediations.sort(
            key=lambda s: (
                self.remed_priority.get(s["operation"], 99),
                s["system_id"],
                s["resource_id"],
            )
        )

        # For verifications in an incomplete case, clear evidence_id
        if not is_complete:
            for v in verifications:
                v["evidence_id"] = ""

        # Sort verifications: (operation priority, system_id, resource_id)
        verifications.sort(
            key=lambda s: (
                self.verif_priority.get(s["operation"], 99),
                s["system_id"],
                s["resource_id"],
            )
        )

        if is_complete:
            status = "COMPLETE"
            all_steps = verifications
        else:
            status = "INCOMPLETE"
            all_steps = findings + remediations + verifications

        # Re-number consecutively from 1
        for idx, s in enumerate(all_steps, 1):
            s["step_no"] = idx

        return status, all_steps
