import pandas as pd
import sys
sys.path.insert(0, './code')
from identity import IdentityGraph
from evidence_store import EvidenceStore

idg = IdentityGraph('dataset/user_identities.csv', 'dataset/user_audit_log.csv')
store = EvidenceStore('dataset', idg)

# Let's inspect all deletion_worker events around 2026-09-02 and 2026-08-30
df = pd.read_csv('dataset/system_activity.csv')
del_workers = df[df["source_system"] == "deletion_worker"].copy()
del_workers["dt"] = pd.to_datetime(del_workers["event_time"])

for target_date in ['2026-08-30', '2026-09-02', '2026-09-12']:
    print(f"\n=== Date: {target_date} ===")
    sub = del_workers[del_workers["event_time"].str.startswith(target_date)].sort_values("dt")
    for _, r in sub.iterrows():
        res = r['resource_id']
        u = store.resource_to_user.get(res)
        print(f"  {r['event_time']} | {r['target_system']:<20} | {res:<16} | user: {u}")
