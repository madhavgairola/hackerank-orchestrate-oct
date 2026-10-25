import csv
import json
import sys
sys.path.insert(0, './code')
from identity import IdentityGraph
from evidence_store import EvidenceStore

idg = IdentityGraph('dataset/user_identities.csv', 'dataset/user_audit_log.csv')
store = EvidenceStore('dataset', idg)

with open('dataset/sample_deletion_requests.csv', 'r', encoding='utf-8') as f:
    reqs = {r['case_id']: r for r in csv.DictReader(f)}

with open('dataset/sample_output.csv', 'r', encoding='utf-8') as f:
    gt = {r['case_id']: json.loads(r['steps_json']) for r in csv.DictReader(f)}

print("Checking if any GT resource has evidence before requested_at:")
for cid, steps in gt.items():
    req = reqs[cid]
    req_at = req['requested_at']
    u = idg.resolve_user(req['email'])
    all_user_items = [it for it in store.items if it.user_id == u.user_id]
    for s in steps:
        res_id = s['resource_id']
        res_items = [it for it in all_user_items if it.resource_id == res_id]
        if res_items:
            min_cap = min(it.captured_at for it in res_items)
            if min_cap < req_at:
                print(f"  {cid}: {res_id} has evidence at {min_cap} < {req_at}")
