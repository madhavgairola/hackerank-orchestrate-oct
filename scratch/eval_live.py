import json
import pandas as pd
import sys
sys.path.insert(0, 'code')
from identity import IdentityGraph
from evidence_store import EvidenceStore
from policy_engine import PolicyEngine

idg = IdentityGraph('dataset/user_identities.csv', 'dataset/user_audit_log.csv')
store = EvidenceStore('dataset', idg)
engine = PolicyEngine('dataset/deletion_rules.csv', idg, store)

df_sample = pd.read_csv('dataset/sample_deletion_requests.csv')
df_true = pd.read_csv('dataset/sample_output.csv').set_index('case_id')

matches_count = 0
for _, req in df_sample.iterrows():
    cid = req['case_id']
    status, steps = engine.evaluate_request(req.to_dict())
    t_status = df_true.loc[cid, 'deletion_status']
    t_steps = json.loads(df_true.loc[cid, 'steps_json'])
    p_canon = [{k: s[k] for k in sorted(s.keys())} for s in steps]
    t_canon = [{k: s[k] for k in sorted(s.keys())} for s in t_steps]
    m = (status == t_status and p_canon == t_canon)
    if m:
        matches_count += 1
    else:
        print(f"Mismatch: {cid} (pred {len(steps)} vs true {len(t_steps)})")

print(f"\nCurrent Matches: {matches_count} / {len(df_sample)}")
