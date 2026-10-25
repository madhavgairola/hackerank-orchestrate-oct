import sys
sys.path.insert(0, './code')
import csv
import json
from identity import IdentityGraph

idg = IdentityGraph('dataset/user_identities.csv', 'dataset/user_audit_log.csv')
cases = [
    ('case_11', 'novak.tomasz@icloud.com'),
    ('case_24', 'keiko.nakamura@gmail.com'),
    ('case_25', 's.yoon04@gmail.com'),
    ('case_26', 'almeida.mariana@gmail.com'),
    ('case_28', 'smartinez6461@gmail.com'),
    ('case_29', 'noah.f438085@outlook.com'),
]

# Read sample_output.csv
gt_by_case = {}
with open('dataset/sample_output.csv', 'r', encoding='utf-8') as f:
    for r in csv.DictReader(f):
        gt_by_case[r['case_id']] = json.loads(r['steps_json'])

# Read sample_deletion_requests.csv
reqs_by_case = {}
with open('dataset/sample_deletion_requests.csv', 'r', encoding='utf-8') as f:
    for r in csv.DictReader(f):
        reqs_by_case[r['case_id']] = r

print("=== INSPECTING RANK 1 CASES ===")
for cid, email in cases:
    req = reqs_by_case.get(cid, {})
    u = idg.resolve_user(email)
    uid = u.user_id if u else "None"
    gt_steps = gt_by_case.get(cid, [])
    gt_analytics = [s['resource_id'] for s in gt_steps if s['system_id'] == 'analytics_platform']
    print(f"\n--- {cid}: {email} (uid: {uid}) ---")
    print(f"  Requested: {req.get('requested_at')} | Reported: {req.get('reported_at')} ({req.get('reported_status')}) | Audit: {req.get('audit_at')}")
    print(f"  GT Analytics resources: {gt_analytics}")
    print(f"  GT All resources: {[(s['system_id'], s['resource_id']) for s in gt_steps]}")
