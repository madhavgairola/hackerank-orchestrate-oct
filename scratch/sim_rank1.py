import pandas as pd
import sys
sys.path.insert(0, './code')
from identity import IdentityGraph
from evidence_store import EvidenceStore

idg = IdentityGraph('dataset/user_identities.csv', 'dataset/user_audit_log.csv')
store = EvidenceStore('dataset', idg)

# Inspect current assignments for Rank 1 cases
for cid, email in [
    ('case_11', 'novak.tomasz@icloud.com'),
    ('case_24', 'keiko.nakamura@gmail.com'),
    ('case_25', 's.yoon04@gmail.com'),
    ('case_26', 'almeida.mariana@gmail.com'),
    ('case_28', 'smartinez6461@gmail.com'),
    ('case_29', 'noah.f438085@outlook.com'),
]:
    u = idg.resolve_user(email)
    uid = u.user_id if u else "None"
    res = store.user_to_resources.get(uid, set())
    ana = [r for r in res if r.startswith("analytics_")]
    print(f"{cid} ({uid}): {ana}")
