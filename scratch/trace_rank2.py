import sys
sys.path.insert(0, './code')
import csv
import json
from identity import IdentityGraph
from evidence_store import EvidenceStore
from policy_engine import PolicyEngine

idg = IdentityGraph('dataset/user_identities.csv', 'dataset/user_audit_log.csv')
store = EvidenceStore('dataset', idg)
engine = PolicyEngine('dataset/deletion_rules.csv', idg, store)

cases = ['case_17', 'case_23']
req_data = {}
with open('dataset/sample_deletion_requests.csv', 'r', encoding='utf-8') as f:
    for r in csv.DictReader(f):
        if r['case_id'] in cases:
            req_data[r['case_id']] = r

gt_data = {}
with open('dataset/sample_output.csv', 'r', encoding='utf-8') as f:
    for r in csv.DictReader(f):
        if r['case_id'] in cases:
            gt_data[r['case_id']] = (r['deletion_status'], json.loads(r['steps_json']))

print("=== TRACING RANK 2 CASES ===")
for cid in cases:
    req = req_data[cid]
    status, steps = engine.evaluate_request(req)
    gt_stat, gt_steps = gt_data[cid]
    u = idg.resolve_user(req['email'])
    print(f"\n==================== {cid} ====================")
    print(f"Request: email={req['email']}, req_at={req['requested_at']}, rep_at={req['reported_at']} ({req['reported_status']}), audit_at={req['audit_at']}")
    print(f"Resolved User: {u.user_id if u else 'None'}")
    print(f"User linked resources in store: {store.user_to_resources.get(u.user_id if u else '')}")
    
    # Compare steps
    print(f"\nPredicted ({status}, {len(steps)} steps):")
    for s in steps:
        print(f"  {s['phase'][:4]} {s['system_id']}:{s['resource_id']} {s['operation']} {s['state']} ev={s['evidence_id']}")
    print(f"\nGround Truth ({gt_stat}, {len(gt_steps)} steps):")
    for s in gt_steps:
        print(f"  {s['phase'][:4]} {s['system_id']}:{s['resource_id']} {s['operation']} {s['state']} ev={s['evidence_id']}")
