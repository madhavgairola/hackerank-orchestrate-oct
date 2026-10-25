import csv
import json
import pandas as pd

with open('dataset/sample_deletion_requests.csv', 'r', encoding='utf-8') as f:
    reqs = {r['case_id']: r for r in csv.DictReader(f)}

manifest = {}
with open('dataset/evidence_files.csv', 'r', encoding='utf-8') as f:
    for r in csv.DictReader(f):
        manifest[r['file_id']] = r['captured_at']

with open('dataset/sample_output.csv', 'r', encoding='utf-8') as f:
    for r in csv.DictReader(f):
        cid = r['case_id']
        req = reqs[cid]
        req_at = req['requested_at']
        steps = json.loads(r['steps_json'])
        for s in steps:
            ev = s.get('evidence_id')
            if ev and ev in manifest:
                ev_cap = manifest[ev]
                if ev_cap < req_at:
                    print(f"Case {cid}: step {s['operation']} {s['resource_id']} cited {ev} (captured {ev_cap} < requested {req_at})")
