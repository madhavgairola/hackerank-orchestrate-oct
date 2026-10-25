import csv
import json

pred_path = 'scratch/sample_pred.csv'
truth_path = 'dataset/sample_output.csv'

with open(pred_path, 'r', encoding='utf-8') as f:
    preds = {row['case_id']: (row['deletion_status'], json.loads(row['steps_json'])) for row in csv.DictReader(f)}

with open(truth_path, 'r', encoding='utf-8') as f:
    truths = {row['case_id']: (row['deletion_status'], json.loads(row['steps_json'])) for row in csv.DictReader(f)}

print(f"Total cases: {len(preds)}")
mismatches = []
for cid in sorted(truths.keys()):
    p_status, p_steps = preds.get(cid, ('', []))
    t_status, t_steps = truths[cid]
    
    if p_status != t_status or p_steps != t_steps:
        mismatches.append((cid, p_status, t_status, p_steps, t_steps))

print(f"Cases with step or status mismatches: {len(mismatches)} / {len(truths)}")
for cid, p_status, t_status, p_steps, t_steps in mismatches:
    print('='*70)
    print(f"Case {cid}: Status Pred={p_status}, Truth={t_status} | Step count Pred={len(p_steps)}, Truth={len(t_steps)}")
    max_len = max(len(p_steps), len(t_steps))
    print(f"{'Pred Step':<42} | {'Truth Step':<42}")
    print('-'*87)
    for i in range(max_len):
        p_str = ''
        if i < len(p_steps):
            ps = p_steps[i]
            p_str = f"{ps['phase'][:4]} {ps['system_id']}:{ps['resource_id']} {ps['operation'][:12]} {ps['evidence_id']}"
        t_str = ''
        if i < len(t_steps):
            ts = t_steps[i]
            t_str = f"{ts['phase'][:4]} {ts['system_id']}:{ts['resource_id']} {ts['operation'][:12]} {ts['evidence_id']}"
        mark = '  ' if p_str == t_str else '!='
        print(f"{p_str:<42} {mark} {t_str:<42}")
