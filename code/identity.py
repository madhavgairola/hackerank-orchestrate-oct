"""
Identity Resolution Layer for Ghost Data Still Exists.
Constructs a deterministic identity graph combining current snapshots
(user_identities.csv) and historical changes (user_audit_log.csv).
"""

import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
import pandas as pd


def normalize_email(email: Optional[str]) -> str:
    """Normalizes an email address to lowercase stripped format."""
    if not email or pd.isna(email):
        return ""
    return str(email).strip().lower()


def normalize_phone(phone: Optional[str]) -> str:
    """Normalizes phone numbers, stripping whitespace while preserving digits and +."""
    if not phone or pd.isna(phone):
        return ""
    return str(phone).strip()


def normalize_hash(h: Optional[str]) -> str:
    """Normalizes an email hash."""
    if not h or pd.isna(h):
        return ""
    return str(h).strip().lower()


@dataclass
class UserIdentity:
    user_id: str
    primary_name: str = ""
    primary_email: str = ""
    primary_phone: str = ""
    primary_hash: str = ""
    updated_at: str = ""
    names: Set[str] = field(default_factory=set)
    emails: Set[str] = field(default_factory=set)
    phones: Set[str] = field(default_factory=set)
    hashes: Set[str] = field(default_factory=set)

    def matches(self, query: str) -> bool:
        """Checks if a string query matches any of this user's identifiers."""
        if not query:
            return False
        q_norm = query.strip()
        q_lower = q_norm.lower()

        if q_norm == self.user_id:
            return True
        if q_lower in self.emails:
            return True
        if q_norm in self.phones:
            return True
        if q_lower in self.hashes:
            return True
        if q_lower in self.names:
            return True
        return False


class IdentityGraph:
    """
    Deterministic identity graph mapping all current and historical identifiers
    to a canonical UserIdentity.
    """

    def __init__(self, identities_csv: str, audit_log_csv: str):
        self.identities_csv = identities_csv
        self.audit_log_csv = audit_log_csv
        self.users: Dict[str, UserIdentity] = {}
        self.email_to_uid: Dict[str, str] = {}
        self.phone_to_uid: Dict[str, str] = {}
        self.hash_to_uid: Dict[str, str] = {}

        self._build_graph()

    def _build_graph(self) -> None:
        # 1. Ingest current identities
        if os.path.exists(self.identities_csv):
            df_ident = pd.read_csv(self.identities_csv)
            for _, r in df_ident.iterrows():
                uid = str(r["user_id"]).strip()
                name = str(r["name"]).strip() if pd.notna(r["name"]) else ""
                email = normalize_email(r["email"])
                phone = normalize_phone(r["phone"])
                email_hash = normalize_hash(r["email_hash"])
                updated_at = str(r["updated_at"]).strip() if pd.notna(r["updated_at"]) else ""

                user = UserIdentity(
                    user_id=uid,
                    primary_name=name,
                    primary_email=email,
                    primary_phone=phone,
                    primary_hash=email_hash,
                    updated_at=updated_at,
                )
                if name:
                    user.names.add(name.lower())
                if email:
                    user.emails.add(email)
                if phone:
                    user.phones.add(phone)
                if email_hash:
                    user.hashes.add(email_hash)

                self.users[uid] = user

        # 2. Ingest historical changes from user_audit_log.csv
        if os.path.exists(self.audit_log_csv):
            df_audit = pd.read_csv(self.audit_log_csv)
            for _, r in df_audit.iterrows():
                uid = str(r["user_id"]).strip()
                field_name = str(r["field_name"]).strip()
                if uid not in self.users:
                    self.users[uid] = UserIdentity(user_id=uid)

                user = self.users[uid]
                for raw_val in [r["old_value"], r["new_value"]]:
                    if pd.isna(raw_val):
                        continue
                    if field_name == "email":
                        val = normalize_email(raw_val)
                        if val:
                            user.emails.add(val)
                    elif field_name == "phone":
                        val = normalize_phone(raw_val)
                        if val:
                            user.phones.add(val)
                    elif field_name == "email_hash":
                        val = normalize_hash(raw_val)
                        if val:
                            user.hashes.add(val)
                    elif field_name == "name":
                        val = str(raw_val).strip().lower()
                        if val:
                            user.names.add(val)

        # 3. Populate reverse indexes
        for uid, user in self.users.items():
            for em in user.emails:
                self.email_to_uid[em] = uid
            for ph in user.phones:
                self.phone_to_uid[ph] = uid
            for h in user.hashes:
                self.hash_to_uid[h] = uid

    def resolve_user(self, identifier: Optional[str]) -> Optional[UserIdentity]:
        """
        Resolves an identifier (email, phone, hash, or user_id) to the canonical UserIdentity.
        Case-insensitive for emails and hashes.
        """
        if not identifier:
            return None
        ident_clean = str(identifier).strip()
        ident_lower = ident_clean.lower()

        # Check direct user_id
        if ident_clean in self.users:
            return self.users[ident_clean]

        # Check email
        if ident_lower in self.email_to_uid:
            return self.users[self.email_to_uid[ident_lower]]

        # Check phone
        if ident_clean in self.phone_to_uid:
            return self.users[self.phone_to_uid[ident_clean]]

        # Check hash
        if ident_lower in self.hash_to_uid:
            return self.users[self.hash_to_uid[ident_lower]]

        return None

    def get_user(self, user_id: str) -> Optional[UserIdentity]:
        return self.users.get(user_id)

    def all_users(self) -> List[UserIdentity]:
        return list(self.users.values())
