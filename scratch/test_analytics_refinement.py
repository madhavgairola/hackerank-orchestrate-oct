import pandas as pd
import sys
sys.path.insert(0, './code')
from identity import IdentityGraph
from evidence_store import EvidenceStore

idg = IdentityGraph('dataset/user_identities.csv', 'dataset/user_audit_log.csv')
store = EvidenceStore('dataset', idg)

df = pd.read_csv('dataset/system_activity.csv')
del_workers = df[df["source_system"] == "deletion_worker"].copy()
del_workers["dt"] = pd.to_datetime(del_workers["event_time"])
del_workers = del_workers.sort_values("dt")

dw_acc = del_workers[del_workers["target_system"] == "account_service"]
dw_ana = del_workers[del_workers["target_system"] == "analytics_platform"]
dw_downstream = del_workers[del_workers["target_system"].isin(["support_platform", "integration_service", "backup_service"])]

assigned_accounts = set()
sim_user_to_ana = {}

for _, ana in dw_ana.iterrows():
    ana_res = str(ana["resource_id"]).strip()
    ana_dt = ana["dt"]
    
    # 1. Check downstream resources in tight window [-15m, +45m]
    near_downstream = dw_downstream[
        (dw_downstream["dt"] >= ana_dt - pd.Timedelta(minutes=15))
        & (dw_downstream["dt"] <= ana_dt + pd.Timedelta(minutes=45))
    ]
    chosen_uid = None
    chosen_acc = None
    for _, ds in near_downstream.iterrows():
        ds_res = str(ds["resource_id"]).strip()
        u_owner = store.resource_to_user.get(ds_res)
        if u_owner:
            has_ana = any(r.startswith("analytics_") for r in store.user_to_resources.get(u_owner, set())) or (u_owner in sim_user_to_ana)
            if not has_ana:
                chosen_uid = u_owner
                # find their account
                u_accs = [r for r in store.user_to_resources.get(u_owner, set()) if r.startswith("account_")]
                if u_accs:
                    chosen_acc = u_accs[0]
                break
                
    # 2. If not found via downstream, match unassigned preceding accounts
    if not chosen_uid:
        prec_acc = dw_acc[(dw_acc["dt"] <= ana_dt) & (dw_acc["dt"] >= ana_dt - pd.Timedelta(minutes=60))]
        unassigned_accs = [
            r for _, r in prec_acc.iterrows()
            if str(r["resource_id"]).strip() in store.resource_to_user
            and str(r["resource_id"]).strip() not in assigned_accounts
        ]
        # Filter to accounts whose owner has NO analytics
        cand_list = []
        for u_acc in unassigned_accs:
            acc_cand = str(u_acc["resource_id"]).strip()
            c_uid = store.resource_to_user.get(acc_cand)
            if c_uid:
                has_ana = any(r.startswith("analytics_") for r in store.user_to_resources.get(c_uid, set())) or (c_uid in sim_user_to_ana)
                if not has_ana:
                    cand_list.append((acc_cand, c_uid, u_acc["dt"]))
        if cand_list:
            # Sort by FIFO submission time (earliest first in batch)
            cand_list.sort(key=lambda x: x[2])
            chosen_acc, chosen_uid, _ = cand_list[0]
            
    if chosen_uid:
        sim_user_to_ana.setdefault(chosen_uid, []).append(ana_res)
        if chosen_acc:
            assigned_accounts.add(chosen_acc)

print("\n--- SIMULATION RESULTS FOR TARGET USERS ---")
for cid, email in [
    ('case_11', 'novak.tomasz@icloud.com'),
    ('case_24', 'keiko.nakamura@gmail.com'),
    ('case_25', 's.yoon04@gmail.com'),
    ('case_26', 'almeida.mariana@gmail.com'),
    ('case_28', 'smartinez6461@gmail.com'),
    ('case_29', 'noah.f438085@outlook.com'),
]:
    u = idg.resolve_user(email)
    uid = u.user_id
    existing_ana = [r for r in store.user_to_resources.get(uid, set()) if r.startswith("analytics_") and r not in ['analytics_4566', 'analytics_5715', 'analytics_6077']]
    sim_ana = sim_user_to_ana.get(uid, [])
    print(f"{cid} ({uid}): existing={existing_ana}, sim_assigned={sim_ana}")
