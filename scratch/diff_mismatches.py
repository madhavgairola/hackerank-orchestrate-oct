import json
import pandas as pd

df_pred = pd.read_csv('scratch/sample_pred.csv').set_index('case_id')
df_true = pd.read_csv('dataset/sample_output.csv').set_index('case_id')

target_cases = ['case_03', 'case_18', 'case_20', 'case_21', 'case_28', 'case_29', 'case_31']

for cid in target_cases:
    p_status = df_pred.loc[cid, 'deletion_status']
    t_status = df_true.loc[cid, 'deletion_status']
    p_steps = json.loads(df_pred.loc[cid, 'steps_json'])
    t_steps = json.loads(df_true.loc[cid, 'steps_json'])
    print(f"\n=======================================================")
    print(f"CASE {cid}: Pred Status={p_status}, True Status={t_status}")
    print(f"Step Count: Pred={len(p_steps)}, True={len(t_steps)}")
    
    max_len = max(len(p_steps), len(t_steps))
    for i in range(max_len):
        ps = p_steps[i] if i < len(p_steps) else None
        ts = t_steps[i] if i < len(t_steps) else None
        if ps == ts:
            continue
        print(f"  Step {i+1}:")
        if ps is None:
            print(f"    PRED: [MISSING]")
            print(f"    TRUE: {ts}")
        elif ts is None:
            print(f"    PRED: {ps}")
            print(f"    TRUE: [EXTRA]")
        else:
            diffs = []
            for k in ['phase', 'system_id', 'resource_id', 'operation', 'state', 'evidence_id']:
                if ps.get(k) != ts.get(k):
                    diffs.append(f"{k}: (Pred='{ps.get(k)}' vs True='{ts.get(k)}')")
            print(f"    Diffs: {', '.join(diffs)}")
            print(f"    PRED: {ps}")
            print(f"    TRUE: {ts}")
