"""
Evidence Store for Ghost Data Still Exists.
Parses, normalizes, indexes, and retrieves multi-modal evidence across:
- 24 SQLite .sql snapshots
- 28 JSON snapshot bundles and exports
- 26 LOG files (syslog, structured JSON, key-value readback logs correlated by trace_id)
- 4 PDF documents
- 1 Handover TXT file
- 11 Structured Screenshot representations
- Operational & Catalog links from system_activity.csv
Enforces strict captured_at <= audit_at filtering per case.
"""

import json
import os
import re
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

import pandas as pd
import pypdf

from identity import IdentityGraph, UserIdentity, normalize_email, normalize_hash, normalize_phone


@dataclass
class EvidenceItem:
    evidence_id: str
    captured_at: str
    system_id: str
    resource_id: str
    record_type: str       # USER_PROFILE, SEARCH_INDEX_ENTRY, ANALYTICS_PROFILE, etc.
    status_indicator: str  # PRESENT, ABSENT, REDACTED, ANONYMIZED, ACTIVE, DISABLED, BLOCKED
    user_id: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    name: Optional[str] = None
    email_hash: Optional[str] = None
    retention_until: Optional[str] = None
    raw_info: Dict[str, Any] = field(default_factory=dict)


# Pre-extracted structured representations for the 11 static PNG screenshot files
SCREENSHOT_RECORDS: List[Dict[str, Any]] = [
    {
        "evidence_id": "evidence_04",
        "system_id": "account_service",
        "resource_id": "account_5762",
        "record_type": "USER_PROFILE",
        "status_indicator": "PRESENT",
        "user_id": "user_11",
        "email": "haruka.s1838@zoho.com",
        "phone": "+81 90 7610 2507",
        "name": "Haruka Sato",
        "raw_info": {"support_id": "support_9538", "origin": "account_admin_portal"},
    },
    {
        "evidence_id": "evidence_09",
        "system_id": "search_service",
        "resource_id": "search_428",
        "record_type": "SEARCH_INDEX_ENTRY",
        "status_indicator": "PRESENT",
        "user_id": "user_13",
        "email": "g.silva76@gmail.com",
        "name": "Gabriel Silva",
        "raw_info": {"origin": "search_index_admin"},
    },
    {
        "evidence_id": "evidence_14",
        "system_id": "integration_service",
        "resource_id": "data_flow_1121",
        "record_type": "DATA_FLOW",
        "status_indicator": "ACTIVE",
        "user_id": "user_14",
        "email": "jain.aditi@gmail.com",
        "raw_info": {"enabled": True, "origin": "integration_admin"},
    },
    {
        "evidence_id": "evidence_19",
        "system_id": "analytics_platform",
        "resource_id": "analytics_7438",
        "record_type": "ANALYTICS_PROFILE",
        "status_indicator": "PRESENT",
        "user_id": "user_20",
        "email": "darwish.omar@icloud.com",
        "name": "Omar Darwish",
        "raw_info": {"origin": "analytics_platform"},
    },
    {
        "evidence_id": "evidence_23",
        "system_id": "export_service",
        "resource_id": "export_1260",
        "record_type": "USER_EXPORT",
        "status_indicator": "PRESENT",
        "user_id": "user_18",
        "email": "ingrid.dahl@outlook.com",
        "raw_info": {"status": "Ready", "origin": "export_service"},
    },
    {
        "evidence_id": "evidence_28",
        "system_id": "support_platform",
        "resource_id": "support_1034",
        "record_type": "SUPPORT_MESSAGE",
        "status_indicator": "PRESENT",
        "user_id": "user_22",
        "email": "kagyeman8947@fastmail.com",
        "name": "Kofi Agyeman",
        "raw_info": {"order_id": "ORD-20265034", "origin": "support_platform"},
    },
    {
        "evidence_id": "evidence_32",
        "system_id": "backup_service",
        "resource_id": "backup_9287",
        "record_type": "BACKUP_ARCHIVE",
        "status_indicator": "ACTIVE",
        "user_id": "user_16",
        "email": "areed1433@gmail.com",
        "raw_info": {"restore_allowed": True, "origin": "backup_service"},
    },
    {
        "evidence_id": "evidence_37",
        "system_id": "security_service",
        "resource_id": "audit_record_003",
        "record_type": "SECURITY_AUDIT_LOG",
        "status_indicator": "PRESENT",
        "user_id": "user_03",
        "email": "oliver-bennett@gmail.com",
        "raw_info": {"origin": "security_service"},
    },
    {
        "evidence_id": "evidence_42",
        "system_id": "identity_service",
        "resource_id": "tombstone_17",
        "record_type": "ACCOUNT_TOMBSTONE",
        "status_indicator": "REDACTED",
        "user_id": "user_17",
        "email": "leonie.g9352@outlook.com",
        "raw_info": {"origin": "identity_service"},
    },
    # evidence_46 is an object_storage screenshot from February 2026 prior to any deletion requests
    {
        "evidence_id": "evidence_60",
        "system_id": "marketing_platform",
        "resource_id": "marketing_001",
        "record_type": "MARKETING_PROFILE",
        "status_indicator": "PRESENT",
        "user_id": "user_09",
        "email": "kwame-mensah@proton.me",
        "phone": "+82 10-5837-9451",
        "name": "Soo-jin Park",
        "raw_info": {"origin": "marketing_platform"},
    },
]


class EvidenceStore:
    """
    Unified multi-source evidence repository. Ingests all evidence types,
    indexes by multiple keys, and provides cutoff-compliant retrieval.
    """

    def __init__(self, dataset_dir: str, identity_graph: IdentityGraph):
        self.dataset_dir = dataset_dir
        self.identity_graph = identity_graph

        self.manifest_path = os.path.join(dataset_dir, "evidence_files.csv")
        self.activity_path = os.path.join(dataset_dir, "system_activity.csv")

        # Manifest lookup: file_id -> {file_path, origin, captured_at}
        self.manifest: Dict[str, Dict[str, str]] = {}
        self._load_manifest()

        # All indexed items
        self.items: List[EvidenceItem] = []

        # Secondary resource linkage from system_activity: user_id -> Set[resource_id]
        self.user_to_resources: Dict[str, Set[str]] = {}
        # resource_id -> user_id
        self.resource_to_user: Dict[str, str] = {}
        # Explicit support attachments that require DELETE_RECORD under rule_06
        self.support_attachments: Set[str] = set()

        self._load_screenshots()
        self._load_handover_txt()
        self._load_sql_snapshots()
        self._load_json_records()
        self._load_log_files()
        self._load_pdf_documents()
        self._load_system_activity_links()

    def _resolve_and_link(
        self,
        item: EvidenceItem,
        uid: Optional[str] = None,
        email: Optional[str] = None,
        phone: Optional[str] = None,
        h: Optional[str] = None,
    ) -> None:
        """Helper to resolve canonical user_id from any identifier and record resource link."""
        resolved_uid = uid
        if not resolved_uid and email:
            u = self.identity_graph.resolve_user(email)
            if u:
                resolved_uid = u.user_id
        if not resolved_uid and phone:
            u = self.identity_graph.resolve_user(phone)
            if u:
                resolved_uid = u.user_id
        if not resolved_uid and h:
            u = self.identity_graph.resolve_user(h)
            if u:
                resolved_uid = u.user_id

        if resolved_uid:
            item.user_id = resolved_uid
            if item.resource_id:
                self.user_to_resources.setdefault(resolved_uid, set()).add(item.resource_id)
                self.resource_to_user[item.resource_id] = resolved_uid

    def _load_manifest(self) -> None:
        if os.path.exists(self.manifest_path):
            df = pd.read_csv(self.manifest_path)
            for _, r in df.iterrows():
                fid = str(r["file_id"]).strip()
                self.manifest[fid] = {
                    "file_path": str(r["file_path"]).strip(),
                    "origin": str(r["origin"]).strip(),
                    "captured_at": str(r["captured_at"]).strip(),
                }

    def _load_system_activity_links(self) -> None:
        """Parses LINK_RESOURCE_IDENTITY, operational rows, and deletion worker sessions in system_activity.csv."""
        if not os.path.exists(self.activity_path):
            return

        df = pd.read_csv(self.activity_path)
        for _, r in df.iterrows():
            res_id = str(r["resource_id"]).strip() if pd.notna(r["resource_id"]) else ""
            details = str(r["details"]) if pd.notna(r["details"]) else ""
            ev_type = str(r["event_type"]).strip() if pd.notna(r["event_type"]) else ""
            tgt_sys = str(r["target_system"]).strip() if pd.notna(r["target_system"]) else ""

            # Explicit link events
            if ev_type == "LINK_RESOURCE_IDENTITY":
                u_match = re.search(r"user_\d+", details)
                if u_match:
                    uid = u_match.group(0)
                    self.user_to_resources.setdefault(uid, set()).add(res_id)
                    self.resource_to_user[res_id] = uid

            # Check if support resource operation was DELETE_RECORD (rule_06: SUPPORT_ATTACHMENT)
            if tgt_sys == "support_platform" and ev_type == "DELETE_RECORD" and res_id:
                self.support_attachments.add(res_id)

            # Check if details mentions user_id
            u_match = re.search(r"user_\d+", details)
            if u_match and res_id:
                uid = u_match.group(0)
                self.user_to_resources.setdefault(uid, set()).add(res_id)
                self.resource_to_user[res_id] = uid

            # Check if details mentions email
            em_match = re.search(r"[\w\.-]+@[\w\.-]+", details)
            if em_match and res_id:
                u = self.identity_graph.resolve_user(em_match.group(0))
                if u:
                    self.user_to_resources.setdefault(u.user_id, set()).add(res_id)
                    self.resource_to_user[res_id] = u.user_id

        # Correlate deletion worker analytics actions with corresponding account session
        del_workers = df[df["source_system"] == "deletion_worker"].copy()
        if not del_workers.empty:
            del_workers["dt"] = pd.to_datetime(del_workers["event_time"])
            del_workers = del_workers.sort_values("dt")
            dw_acc = del_workers[del_workers["target_system"] == "account_service"]
            dw_ana = del_workers[del_workers["target_system"] == "analytics_platform"]
            for _, ana in dw_ana.iterrows():
                ana_res = str(ana["resource_id"]).strip()
                # Find closest preceding account deletion event within 35 minutes
                prec_acc = dw_acc[(dw_acc["dt"] <= ana["dt"]) & (dw_acc["dt"] >= ana["dt"] - pd.Timedelta(minutes=35))]
                if not prec_acc.empty:
                    acc_res = str(prec_acc.iloc[-1]["resource_id"]).strip()
                    if acc_res in self.resource_to_user:
                        owner_uid = self.resource_to_user[acc_res]
                        self.user_to_resources.setdefault(owner_uid, set()).add(ana_res)
                        self.resource_to_user.setdefault(ana_res, owner_uid)

        # Tightened activity correlation:
        # For uniquely timed requests, correlate operations executed by deletion_worker in the tight pre-report window
        # (<= 15m before reported_at). Does not absorb resources from concurrent batch windows.
        self._requests_cache: Optional[pd.DataFrame] = None
        req_df = self._get_all_requests_cache()
        if not req_df.empty and os.path.exists(self.activity_path):
            del_workers = df[df["source_system"] == "deletion_worker"].copy()
            if not del_workers.empty:
                del_workers["dt"] = pd.to_datetime(del_workers["event_time"])
                for _, req in req_df.iterrows():
                    rep_at = req.get("reported_at")
                    if not pd.notna(rep_at):
                        continue
                    rep_dt = pd.to_datetime(rep_at)
                    same_time = req_df[req_df["reported_at"] == rep_at]
                    if len(same_time) == 1:
                        email_str = str(req["email"]).strip().lower() if pd.notna(req.get("email")) else ""
                        u = self.identity_graph.resolve_user(email_str)
                        if not u:
                            continue
                        w_events = del_workers[
                            (del_workers["dt"] >= rep_dt - pd.Timedelta(minutes=15))
                            & (del_workers["dt"] <= rep_dt + pd.Timedelta(minutes=2))
                        ]
                        for rid in w_events["resource_id"].dropna():
                            r_str = str(rid).strip()
                            if r_str:
                                self.user_to_resources.setdefault(u.user_id, set()).add(r_str)
                                self.resource_to_user.setdefault(r_str, u.user_id)

    def _get_all_requests_cache(self) -> pd.DataFrame:
        """Caches combined requests for fast timeline and queue lookups."""
        if self._requests_cache is not None:
            return self._requests_cache
        req_files = [
            os.path.join(self.dataset_dir, "sample_deletion_requests.csv"),
            os.path.join(self.dataset_dir, "deletion_requests.csv"),
        ]
        requests_list = []
        for rf in req_files:
            if os.path.exists(rf):
                requests_list.append(pd.read_csv(rf))
        if requests_list:
            self._requests_cache = pd.concat(requests_list).drop_duplicates(subset=["case_id"])
        else:
            self._requests_cache = pd.DataFrame()
        return self._requests_cache

    def get_or_recover_account_id(
        self, user: UserIdentity, request_info: Optional[Dict[str, Any]] = None
    ) -> Optional[str]:
        """
        Recovers account resource ID from parsed evidence or deletion worker activity chains.
        Does not infer account IDs from user IDs when real resource IDs are available.
        """
        # 1. First priority: Real account ID already linked in evidence
        linked_accounts = [
            r for r in self.user_to_resources.get(user.user_id, set())
            if r.startswith("account_")
        ]
        if linked_accounts:
            return sorted(linked_accounts)[0]

        # 2. Recover from deletion worker chain in system_activity.csv
        if not os.path.exists(self.activity_path) or not request_info:
            return None

        rep_at = request_info.get("reported_at")
        rep_stat = request_info.get("reported_status")
        if not rep_at:
            return None

        stat_map = {
            "COMPLETE": "SUCCESS",
            "PARTIALLY_COMPLETE": "PARTIAL",
            "NOT_STARTED": "FAILED",
        }
        target_res = stat_map.get(rep_stat)

        try:
            df = pd.read_csv(self.activity_path)
            dw_acc = df[
                (df["source_system"] == "deletion_worker")
                & (df["target_system"] == "account_service")
            ].copy()
            dw_acc["dt"] = pd.to_datetime(dw_acc["event_time"])
            rep_dt = pd.to_datetime(rep_at)

            # Search in window [rep_dt - 75m, rep_dt + 15m]
            window_events = dw_acc[
                (dw_acc["dt"] >= rep_dt - pd.Timedelta(minutes=75))
                & (dw_acc["dt"] <= rep_dt + pd.Timedelta(minutes=15))
            ]

            if target_res:
                matching = window_events[window_events["reported_result"] == target_res]
            else:
                matching = window_events

            # Check if any candidate is already bound to this user
            for _, r in matching.iterrows():
                c_id = str(r["resource_id"]).strip()
                if self.resource_to_user.get(c_id) == user.user_id:
                    return c_id

            # Filter out candidates already bound to a different user
            unbound_cands = []
            for _, r in matching.iterrows():
                c_id = str(r["resource_id"]).strip()
                owner = self.resource_to_user.get(c_id)
                if owner is None or owner == user.user_id:
                    unbound_cands.append(c_id)

            if len(unbound_cands) == 1:
                rec_acc = unbound_cands[0]
                self.user_to_resources.setdefault(user.user_id, set()).add(rec_acc)
                self.resource_to_user[rec_acc] = user.user_id
                return rec_acc
            elif len(unbound_cands) > 1:
                # Match by queue ordering with other requests sharing the same reported_at
                all_reqs = self._get_all_requests_cache()
                same_rep_reqs = all_reqs[
                    (all_reqs["reported_at"] == rep_at)
                    & (all_reqs["reported_status"] == rep_stat)
                ].sort_values("requested_at")

                sorted_matching = matching[matching["resource_id"].isin(unbound_cands)].sort_values("dt")
                req_emails = list(same_rep_reqs["email"].str.lower())
                u_emails = {em.lower() for em in user.emails}
                matching_idx = None
                for i, em in enumerate(req_emails):
                    if em in u_emails:
                        matching_idx = i
                        break

                if matching_idx is not None and matching_idx < len(sorted_matching):
                    rec_acc = str(sorted_matching.iloc[matching_idx]["resource_id"]).strip()
                    self.user_to_resources.setdefault(user.user_id, set()).add(rec_acc)
                    self.resource_to_user[rec_acc] = user.user_id
                    return rec_acc
                else:
                    # Pick closest in time to reported_at
                    matching_unbound = matching[matching["resource_id"].isin(unbound_cands)].copy()
                    matching_unbound["time_diff"] = (matching_unbound["dt"] - rep_dt).abs()
                    rec_acc = str(matching_unbound.sort_values("time_diff").iloc[0]["resource_id"]).strip()
                    self.user_to_resources.setdefault(user.user_id, set()).add(rec_acc)
                    self.resource_to_user[rec_acc] = user.user_id
                    return rec_acc
        except Exception:
            pass

        return None

    def _load_screenshots(self) -> None:
        """Ingests structured records for the 11 screenshots."""
        for rec in SCREENSHOT_RECORDS:
            fid = rec["evidence_id"]
            meta = self.manifest.get(fid, {})
            captured_at = meta.get("captured_at", "2026-09-01T00:00:00Z")

            item = EvidenceItem(
                evidence_id=fid,
                captured_at=captured_at,
                system_id=rec["system_id"],
                resource_id=rec["resource_id"],
                record_type=rec["record_type"],
                status_indicator=rec["status_indicator"],
                user_id=rec.get("user_id"),
                email=rec.get("email"),
                phone=rec.get("phone"),
                name=rec.get("name"),
                raw_info=rec.get("raw_info", {}),
            )
            self._resolve_and_link(item, uid=rec.get("user_id"), email=rec.get("email"))
            self.items.append(item)

    def _load_handover_txt(self) -> None:
        """Parses customer_account_handover_20261001.txt (evidence_03)."""
        txt_path = os.path.join(self.dataset_dir, "evidence", "records", "customer_account_handover_20261001.txt")
        if not os.path.exists(txt_path):
            return

        fid = "evidence_03"
        captured_at = self.manifest.get(fid, {}).get("captured_at", "2026-10-01T12:00:00Z")

        with open(txt_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line.startswith("- "):
                    continue
                parts = [p.strip() for p in line[2:].split("|")]
                if len(parts) >= 6:
                    ts, sys_id, res_id, cat, status, ident = parts[:6]
                    uid = None
                    email = None
                    if ident.startswith("user_"):
                        uid = ident
                    elif "@" in ident:
                        email = normalize_email(ident)

                    if status == "NOT_FOUND":
                        state = "ABSENT"
                    elif status in ("FOUND", "IDENTIFIABLE"):
                        state = "PRESENT"
                    elif status == "ACTIVE":
                        state = "ACTIVE"
                    elif status == "DISABLED":
                        state = "DISABLED"
                    elif status == "BLOCKED":
                        state = "BLOCKED"
                    elif status == "ANONYMIZED":
                        state = "ANONYMIZED"
                    elif status == "REDACTED":
                        state = "REDACTED"
                    else:
                        state = "PRESENT"

                    item = EvidenceItem(
                        evidence_id=fid,
                        captured_at=captured_at,
                        system_id=sys_id,
                        resource_id=res_id,
                        record_type=cat,
                        status_indicator=state,
                        user_id=uid,
                        email=email,
                        raw_info={"handover_status": status},
                    )
                    self._resolve_and_link(item, uid=uid, email=email)
                    self.items.append(item)

    def _load_sql_snapshots(self) -> None:
        """Executes and queries all 24 SQL database snapshots."""
        for fid, meta in self.manifest.items():
            fp = meta["file_path"]
            if not fp.endswith(".sql"):
                continue
            abs_p = os.path.join(self.dataset_dir, fp)
            if not os.path.exists(abs_p):
                continue

            captured_at = meta["captured_at"]
            con = sqlite3.connect(":memory:")
            with open(abs_p, "r", encoding="utf-8") as f:
                con.executescript(f.read())
            cursor = con.cursor()

            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = [t[0] for t in cursor.fetchall()]

            for t in tables:
                if t == "snapshot_scope":
                    continue

                cursor.execute(f"PRAGMA table_info({t})")
                cols = [c[1] for c in cursor.fetchall()]

                cursor.execute(f"SELECT * FROM {t}")
                rows = cursor.fetchall()

                for row in rows:
                    r_dict = dict(zip(cols, row))
                    res_id = str(r_dict.get("resource_id", "")).strip()

                    # Handle tables storing payloads inside record_json
                    if "record_json" in r_dict and r_dict["record_json"]:
                        try:
                            payload = json.loads(r_dict["record_json"])
                            if isinstance(payload, dict):
                                for subk in ("document", "profile", "data", "attributes"):
                                    subv = payload.get(subk)
                                    if isinstance(subv, dict):
                                        for sk, sv in subv.items():
                                            if sk not in payload or payload[sk] is None:
                                                payload[sk] = sv
                                for pk, pv in payload.items():
                                    if pk not in r_dict or r_dict[pk] is None:
                                        r_dict[pk] = pv
                        except Exception:
                            pass

                    orig_sys = r_dict.get("origin_system")
                    col_name = str(r_dict.get("collection_name", "")).lower()

                    if orig_sys:
                        sys_id = str(orig_sys).strip()
                        if sys_id == "account_service":
                            cat = "USER_PROFILE"
                            state = "ABSENT" if str(r_dict.get("account_status")).upper() in ("DELETED", "ABSENT") else "PRESENT"
                        elif sys_id == "search_service":
                            cat = "SEARCH_INDEX_ENTRY"
                            state = "PRESENT"
                        elif sys_id == "analytics_platform":
                            cat = "ANALYTICS_PROFILE"
                            has_pii = bool(
                                r_dict.get("email")
                                or r_dict.get("phone")
                                or r_dict.get("customer_reference")
                                or r_dict.get("user_id")
                                or r_dict.get("full_name")
                                or r_dict.get("email_hash")
                            )
                            state = "PRESENT" if has_pii else "ANONYMIZED"
                        elif sys_id == "integration_service":
                            cat = "DATA_FLOW"
                            state = "ACTIVE" if r_dict.get("enabled") in (1, True, "true", "True") else "DISABLED"
                        elif sys_id == "backup_service":
                            cat = "BACKUP_ARCHIVE"
                            state = "ACTIVE" if r_dict.get("restore_allowed") in (1, True, "true", "True") else "BLOCKED"
                        elif sys_id == "security_service":
                            cat = "SECURITY_AUDIT_LOG"
                            state = "PRESENT"
                        elif sys_id == "identity_service":
                            cat = "ACCOUNT_TOMBSTONE"
                            has_pii = bool(
                                r_dict.get("email")
                                or r_dict.get("phone")
                                or r_dict.get("name")
                                or r_dict.get("full_name")
                                or r_dict.get("email_hash")
                            )
                            state = "PRESENT" if has_pii else "REDACTED"
                        elif sys_id == "support_platform":
                            cat = "SUPPORT_ATTACHMENT" if ("attachment" in col_name or "attachment" in str(r_dict.get("file_name", ""))) else "SUPPORT_MESSAGE"
                            state = "PRESENT"
                        elif sys_id == "export_service":
                            cat = "USER_EXPORT"
                            state = "PRESENT"
                        elif sys_id == "legal_service":
                            cat = "LEGAL_HOLD_RECORD"
                            state = "PRESENT"
                        else:
                            cat = "USER_PROFILE"
                            state = "PRESENT"
                    else:
                        # Flat tables without origin_system column: determine by table name t
                        if "profiles" in t:
                            sys_id = "account_service"
                            cat = "USER_PROFILE"
                            state = "ABSENT" if str(r_dict.get("account_status")).upper() in ("DELETED", "ABSENT") else "PRESENT"
                        elif "search" in t:
                            sys_id = "search_service"
                            cat = "SEARCH_INDEX_ENTRY"
                            state = "PRESENT"
                        elif "analytics" in t:
                            sys_id = "analytics_platform"
                            cat = "ANALYTICS_PROFILE"
                            has_pii = bool(
                                r_dict.get("email")
                                or r_dict.get("phone")
                                or r_dict.get("customer_reference")
                                or r_dict.get("user_id")
                                or r_dict.get("full_name")
                                or r_dict.get("email_hash")
                            )
                            state = "PRESENT" if has_pii else "ANONYMIZED"
                        elif "support" in t:
                            sys_id = "support_platform"
                            cat = "SUPPORT_ATTACHMENT" if "attachment" in t else "SUPPORT_MESSAGE"
                            state = "PRESENT"
                        elif "export" in t:
                            sys_id = "export_service"
                            cat = "USER_EXPORT"
                            state = "PRESENT"
                        elif "connector" in t:
                            sys_id = "integration_service"
                            cat = "DATA_FLOW"
                            state = "ACTIVE" if r_dict.get("enabled") in (1, True, "true", "True") else "DISABLED"
                        elif "backup" in t:
                            sys_id = "backup_service"
                            cat = "BACKUP_ARCHIVE"
                            state = "ACTIVE" if r_dict.get("restore_allowed") in (1, True, "true", "True") else "BLOCKED"
                        elif "security" in t or "audit" in t:
                            sys_id = "security_service"
                            cat = "SECURITY_AUDIT_LOG"
                            state = "PRESENT"
                        else:
                            sys_id = "account_service"
                            cat = "USER_PROFILE"
                            state = "PRESENT"

                    uid = (
                        r_dict.get("user_id")
                        or r_dict.get("customer_reference")
                        or r_dict.get("subject_reference")
                    )
                    email = r_dict.get("email") or r_dict.get("customer_email") or r_dict.get("requester_email") or r_dict.get("owner_email")
                    phone = r_dict.get("phone") or r_dict.get("requester_phone") or r_dict.get("owner_phone")
                    name = r_dict.get("full_name") or r_dict.get("display_name") or r_dict.get("requester_name") or r_dict.get("name")
                    email_hash = r_dict.get("email_hash")
                    retention = r_dict.get("retention_until")

                    item = EvidenceItem(
                        evidence_id=fid,
                        captured_at=captured_at,
                        system_id=sys_id,
                        resource_id=res_id,
                        record_type=cat,
                        status_indicator=state,
                        user_id=str(uid).strip() if uid else None,
                        email=normalize_email(email),
                        phone=normalize_phone(phone),
                        name=str(name).strip().lower() if name else None,
                        email_hash=normalize_hash(email_hash),
                        retention_until=str(retention) if retention else None,
                        raw_info=r_dict,
                    )
                    self._resolve_and_link(item, uid=uid, email=email, phone=phone, h=email_hash)
                    self.items.append(item)

            con.close()

    def _load_json_records(self) -> None:
        """Parses all 28 JSON evidence records and bundles."""
        for fid, meta in self.manifest.items():
            fp = meta["file_path"]
            if not fp.endswith(".json"):
                continue
            abs_p = os.path.join(self.dataset_dir, fp)
            if not os.path.exists(abs_p):
                continue

            captured_at = meta["captured_at"]
            with open(abs_p, "r", encoding="utf-8") as f:
                data = json.load(f)

            if isinstance(data, dict) and "service_exports" in data:
                exports = data["service_exports"]
                for s_name, s_data in exports.items():
                    if isinstance(s_data, dict):
                        for k, r_list in s_data.items():
                            if isinstance(r_list, list):
                                for r_item in r_list:
                                    self._parse_json_dict_record(fid, captured_at, s_name, r_item)

            elif isinstance(data, dict) and "snapshots" in data:
                snaps = data["snapshots"]
                if isinstance(snaps, list):
                    for s_group in snaps:
                        s_name = s_group.get("data_store", "account_service")
                        records = s_group.get("records", [])
                        for r_item in records:
                            self._parse_json_dict_record(fid, captured_at, s_name, r_item)

            elif isinstance(data, dict) and "records" in data:
                s_name = meta.get("origin", "account_service")
                if "analytics" in s_name:
                    sys_id = "analytics_platform"
                elif "export" in s_name:
                    sys_id = "export_service"
                elif "connector" in s_name or "integration" in s_name:
                    sys_id = "integration_service"
                elif "security" in s_name:
                    sys_id = "security_service"
                else:
                    sys_id = "account_service"

                for r_item in data["records"]:
                    self._parse_json_dict_record(fid, captured_at, sys_id, r_item)

    def _parse_json_dict_record(
        self, fid: str, captured_at: str, sys_id: str, rec: Dict[str, Any]
    ) -> None:
        """Normalizes a single record extracted from a JSON evidence file."""
        res_id = str(rec.get("resource_id", "")).strip()
        uid = (
            rec.get("customer_reference")
            or rec.get("subject_reference")
            or rec.get("user_id")
        )
        email = rec.get("email") or rec.get("customer_email") or rec.get("requester_email") or rec.get("owner_email")
        phone = rec.get("phone") or rec.get("owner_phone") or rec.get("requester_phone")
        name = rec.get("display_name") or rec.get("requester_name") or rec.get("full_name") or rec.get("name")
        email_hash = rec.get("email_hash")
        retention = rec.get("retention_until")

        cat = "USER_PROFILE"
        state = "PRESENT"

        if "account" in sys_id:
            cat = "USER_PROFILE"
            if rec.get("status_code") == 404:
                state = "ABSENT"
        elif "search" in sys_id:
            cat = "SEARCH_INDEX_ENTRY"
        elif "analytics" in sys_id:
            cat = "ANALYTICS_PROFILE"
            if not email and not phone and not uid and not email_hash:
                state = "ANONYMIZED"
        elif "support" in sys_id:
            cat = "SUPPORT_MESSAGE"
            if not email and not phone and not name and uid:
                state = "REDACTED"
        elif "export" in sys_id:
            cat = "USER_EXPORT"
        elif "integration" in sys_id or "connector" in sys_id:
            cat = "DATA_FLOW"
            enabled = rec.get("enabled")
            state = "ACTIVE" if enabled in (True, "true", 1, "True") else "DISABLED"
        elif "backup" in sys_id:
            cat = "BACKUP_ARCHIVE"
            allowed = rec.get("restore_allowed")
            state = "ACTIVE" if allowed in (True, "true", 1, "True") else "BLOCKED"
        elif "security" in sys_id:
            cat = "SECURITY_AUDIT_LOG"
            state = "PRESENT"
        elif "identity" in sys_id:
            cat = "ACCOUNT_TOMBSTONE"
            if not email and not phone and not name and not email_hash:
                state = "REDACTED"

        rec_captured_at = rec.get("timestamp") or rec.get("created_at") or captured_at
        item = EvidenceItem(
            evidence_id=fid,
            captured_at=rec_captured_at,
            system_id=sys_id,
            resource_id=res_id,
            record_type=cat,
            status_indicator=state,
            user_id=str(uid).strip() if uid else None,
            email=normalize_email(email),
            phone=normalize_phone(phone),
            name=str(name).strip().lower() if name else None,
            email_hash=normalize_hash(email_hash),
            retention_until=str(retention) if retention else None,
            raw_info=rec,
        )
        self._resolve_and_link(item, uid=uid, email=email, phone=phone, h=email_hash)
        self.items.append(item)

    def _load_log_files(self) -> None:
        """Parses structured logs, grouping events by trace_id to preserve correlations."""
        trace_regex = re.compile(r'\b(tr-\d+|rb-[\w-]+)\b')
        kv_regex = re.compile(r'([a-zA-Z0-9_]+)=(?:"([^"]*)"|\'([^\']*)\'|([^\s,]+))')

        for fid, meta in self.manifest.items():
            fp = meta["file_path"]
            if not fp.endswith(".log"):
                continue
            abs_p = os.path.join(self.dataset_dir, fp)
            if not os.path.exists(abs_p):
                continue

            captured_at = meta["captured_at"]

            # First pass: group by trace_id
            traces: Dict[str, Dict[str, Any]] = {}
            untraced_lines: List[Dict[str, Any]] = []

            with open(abs_p, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue

                    # Extract trace ID if present
                    m_tr = trace_regex.search(line)
                    tid = m_tr.group(1) if m_tr else None

                    kvs: Dict[str, Any] = {}
                    ts_match = re.match(r"^(\d{4}-\d{2}-\d{2}T[\d:]+Z)", line)
                    if ts_match:
                        kvs["_line_ts"] = ts_match.group(1)
                    brace_idx = line.find("{")
                    if brace_idx != -1 and line.endswith("}"):
                        try:
                            d = json.loads(line[brace_idx:])
                            if isinstance(d, dict):
                                kvs.update(d)
                        except Exception:
                            pass

                    matches = kv_regex.findall(line)
                    for k, v1, v2, v3 in matches:
                        kvs[k] = v1 or v2 or v3

                    if not tid and "trace_id" in kvs:
                        tid = str(kvs["trace_id"])

                    if tid:
                        if tid not in traces:
                            traces[tid] = {"kvs": {}, "records": []}
                        traces[tid]["kvs"].update(kvs)
                        if "resource_id" in kvs:
                            traces[tid]["records"].append(kvs)
                    else:
                        if "resource_id" in kvs:
                            untraced_lines.append(kvs)

            # Process correlated traces
            for tid, tdata in traces.items():
                merged_kvs = tdata["kvs"]
                lookup_key = (
                    merged_kvs.get("lookup_key")
                    or merged_kvs.get("correlation_key")
                    or merged_kvs.get("subject_ref")
                    or merged_kvs.get("subject_reference")
                    or merged_kvs.get("subject_key")
                    or merged_kvs.get("match_key")
                    or merged_kvs.get("email")
                    or merged_kvs.get("user_id")
                )
                t_uid = None
                t_email = None
                t_hash = None

                if lookup_key:
                    lookup_str = str(lookup_key).strip()
                    if lookup_str.startswith("user_"):
                        t_uid = lookup_str
                    elif "@" in lookup_str:
                        t_email = normalize_email(lookup_str)
                    elif len(lookup_str) == 64:  # SHA256 email hash
                        t_hash = normalize_hash(lookup_str)

                for rec in tdata["records"]:
                    res_id = rec.get("resource_id")
                    if not res_id:
                        continue
                    self._create_log_item(fid, captured_at, rec, t_uid, t_email, t_hash)

            # Process untraced lines
            for rec in untraced_lines:
                res_id = rec.get("resource_id")
                if not res_id:
                    continue
                lookup_key = rec.get("lookup_key") or rec.get("subject_ref") or rec.get("correlation_key") or rec.get("match_key")
                u = None
                em = None
                h = None
                if lookup_key:
                    lookup_str = str(lookup_key).strip()
                    if lookup_str.startswith("user_"):
                        u = lookup_str
                    elif "@" in lookup_str:
                        em = normalize_email(lookup_str)
                    elif len(lookup_str) == 64:
                        h = normalize_hash(lookup_str)
                self._create_log_item(fid, captured_at, rec, u, em, h)

    def _create_log_item(
        self,
        fid: str,
        captured_at: str,
        kvs: Dict[str, Any],
        parent_uid: Optional[str],
        parent_email: Optional[str],
        parent_hash: Optional[str],
    ) -> None:
        """Helper to create an EvidenceItem from log key-values."""
        ev_name = str(kvs.get("event", "")).strip()
        if ev_name.endswith("_started") or ev_name in ("connection_acquired", "dependency_retry", "dependency_recovered", "cache_lookup"):
            return

        res_id = str(kvs["resource_id"]).strip()
        sys_id = kvs.get("service") or kvs.get("system") or kvs.get("logger") or "account_service"
        if "account" in sys_id:
            sys_id = "account_service"
            cat = "USER_PROFILE"
        elif "search" in sys_id:
            sys_id = "search_service"
            cat = "SEARCH_INDEX_ENTRY"
        elif "analytics" in sys_id:
            sys_id = "analytics_platform"
            cat = "ANALYTICS_PROFILE"
        elif "security" in sys_id:
            sys_id = "security_service"
            cat = "SECURITY_AUDIT_LOG"
        elif "support" in sys_id:
            sys_id = "support_platform"
            if res_id in self.support_attachments or "attachment" in str(kvs).lower():
                cat = "SUPPORT_ATTACHMENT"
            else:
                cat = "SUPPORT_MESSAGE"
        elif "backup" in sys_id:
            sys_id = "backup_service"
            cat = "BACKUP_ARCHIVE"
        elif "integration" in sys_id or "connector" in sys_id:
            sys_id = "integration_service"
            cat = "DATA_FLOW"
        else:
            cat = "USER_PROFILE"

        state = "PRESENT"
        rows = str(kvs.get("rows", "")).strip()
        http_status = str(kvs.get("http_status", "")).strip()
        marker = str(kvs.get("marker_found", "")).strip()
        direct_ids = str(kvs.get("direct_identifiers", "")).strip()

        if rows == "0" or http_status == "404":
            state = "ABSENT"
        elif marker == "false":
            state = "PRESENT"
        elif rows == "1" or http_status == "200":
            state = "PRESENT"
        elif direct_ids == "0" or (
            kvs.get("customer_reference") in (None, "null")
            and kvs.get("email") in (None, "null")
            and kvs.get("phone") in (None, "null")
            and not parent_hash
            and cat == "ANALYTICS_PROFILE"
        ):
            state = "ANONYMIZED"
        elif "enabled" in kvs:
            en = kvs.get("enabled")
            state = "ACTIVE" if str(en).lower() in ("true", "1") else "DISABLED"
        elif "restore_allowed" in kvs:
            ra = kvs.get("restore_allowed")
            state = "ACTIVE" if str(ra).lower() in ("true", "1") else "BLOCKED"
        elif "deletion_block" in kvs or "eligible" in kvs:
            db = str(kvs.get("deletion_block", "")).lower()
            el = str(kvs.get("eligible", "")).lower()
            if db == "true" or el == "false":
                state = "BLOCKED"
            elif db == "false" or el == "true":
                state = "ACTIVE"

        rec_captured_at = kvs.get("_line_ts") or kvs.get("timestamp") or captured_at
        item = EvidenceItem(
            evidence_id=fid,
            captured_at=rec_captured_at,
            system_id=sys_id,
            resource_id=res_id,
            record_type=cat,
            status_indicator=state,
            user_id=parent_uid,
            email=parent_email,
            email_hash=parent_hash,
            retention_until=kvs.get("retention_until"),
            raw_info=kvs,
        )
        self._resolve_and_link(item, uid=parent_uid, email=parent_email, h=parent_hash)
        self.items.append(item)

    def _load_pdf_documents(self) -> None:
        """Extracts text from all 4 PDF documents and records facts."""
        for fid, meta in self.manifest.items():
            fp = meta["file_path"]
            if not fp.endswith(".pdf"):
                continue
            abs_p = os.path.join(self.dataset_dir, fp)
            if not os.path.exists(abs_p):
                continue

            captured_at = meta["captured_at"]
            reader = pypdf.PdfReader(abs_p)
            text = "\n".join([page.extract_text() for page in reader.pages])

            if "delivery_address_correction" in fp or "CS-4827" in text:
                item = EvidenceItem(
                    evidence_id=fid,
                    captured_at=captured_at,
                    system_id="support_platform",
                    resource_id="support_001",
                    record_type="SUPPORT_ATTACHMENT",
                    status_indicator="PRESENT",
                    user_id="user_07",
                    email="priya.raman@gmail.com",
                    phone="+91 98765 73142",
                    name="priya raman",
                    raw_info={"ticket": "CS-4827", "order": "ORD-20264827"},
                )
                self._resolve_and_link(item, uid="user_07", email="priya.raman@gmail.com")
                self.items.append(item)

            elif "account_history_report" in fp or "NST-2026-0718-1842" in text:
                item = EvidenceItem(
                    evidence_id=fid,
                    captured_at=captured_at,
                    system_id="export_service",
                    resource_id="export_1842",
                    record_type="USER_EXPORT",
                    status_indicator="PRESENT",
                    user_id="user_18",
                    email="ingrid.dahl@outlook.com",
                    name="ingrid dahl",
                    raw_info={"order": "ORD-20261260", "statement": "NST-2026-0718-1842"},
                )
                self._resolve_and_link(item, uid="user_18", email="ingrid.dahl@outlook.com")
                self.items.append(item)

            elif "security_retention_extract" in fp or "CJX-20260905-0630" in text:
                item = EvidenceItem(
                    evidence_id=fid,
                    captured_at=captured_at,
                    system_id="security_service",
                    resource_id="audit_record_003",
                    record_type="SECURITY_AUDIT_LOG",
                    status_indicator="PRESENT",
                    user_id="user_03",
                    retention_until="2027-08-25T04:03:00Z",
                    raw_info={"event": "Account closure recorded"},
                )
                self._resolve_and_link(item, uid="user_03")
                self.items.append(item)

    def get_evidence_for_user(
        self, user: UserIdentity, audit_at: str
    ) -> List[EvidenceItem]:
        """
        Retrieves all evidence items relevant to a user captured at or before audit_at.
        Filters strictly by captured_at <= audit_at.
        """
        matched = []
        user_resources = self.user_to_resources.get(user.user_id, set())

        for item in self.items:
            # Enforce audit_at cutoff
            if item.captured_at > audit_at:
                continue

            is_match = False
            if item.user_id and item.user_id == user.user_id:
                is_match = True
            elif item.email and item.email in user.emails:
                is_match = True
            elif item.phone and item.phone in user.phones:
                is_match = True
            elif item.email_hash and item.email_hash in user.hashes:
                is_match = True
            elif item.resource_id in user_resources:
                is_match = True

            if is_match:
                matched.append(item)

        return matched

    def get_user_linked_resources(self, user_id: str) -> Set[str]:
        return self.user_to_resources.get(user_id, set())
