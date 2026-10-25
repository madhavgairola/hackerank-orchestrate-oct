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

for cid in ['case_03', 'case_21', 'case_28', 'case_29', 'case_31']:
    req = df_sample[df_sample['case_id'] == cid].iloc[0].to_dict()
    status, steps = engine.evaluate_request(req)
    t_status = df_true.loc[cid, 'deletion_status']
    t_steps = json.loads(df_true.loc[cid, 'steps_json'])
    p_canon = [{k: s[k] for k in sorted(s.keys())} for s in steps]
    t_canon = [{k: s[k] for k in sorted(s.keys())} for s in t_steps]
    matches = (status == t_status and p_canon == t_canon)
    print(f"{cid}: Match={matches}")
    if not matches:
        print(f"  Pred: {len(steps)} steps vs True: {len(t_steps)} steps")
