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
dw_supp = del_workers[del_workers["target_system"] == "support_platform"]

sim_user_to_ana = {}
assigned_ana = set()
assigned_acc = set()

# 1. Forward-link from known support resources to preceding analytics (within 6 to 8.5 minutes)
for _, sp in dw_supp.iterrows():
    sp_res = str(sp["resource_id"]).strip()
    u_owner = store.resource_to_user.get(sp_res)
    if not u_owner:
        continue
    has_ana = any(r.startswith("analytics_") for r in store.user_to_resources.get(u_owner, set())) or (u_owner in sim_user_to_ana)
    if has_ana:
        continue
    sp_dt = sp["dt"]
    prec_ana = dw_ana[
        (dw_ana["dt"] >= sp_dt - pd.Timedelta(minutes=8.5))
        & (dw_ana["dt"] <= sp_dt - pd.Timedelta(minutes=6))
    ]
    cand_ana = [
        r for _, r in prec_ana.iterrows()
        if str(r["resource_id"]).strip() not in assigned_ana
    ]
    if cand_ana:
        # Pick the one closest to expected ~7 minute cadence
        cand_ana.sort(key=lambda r: abs((sp_dt - r["dt"]).total_seconds() - 449))
        chosen_ana = str(cand_ana[0]["resource_id"]).strip()
        sim_user_to_ana.setdefault(u_owner, []).append(chosen_ana)
        assigned_ana.add(chosen_ana)

# 2. Match remaining unassigned analytics with preceding accounts
for _, ana in dw_ana.iterrows():
    ana_res = str(ana["resource_id"]).strip()
    if ana_res in assigned_ana:
        continue
    ana_dt = ana["dt"]
    prec_acc = dw_acc[(dw_acc["dt"] <= ana_dt) & (dw_acc["dt"] >= ana_dt - pd.Timedelta(minutes=60))]
    unassigned_accs = [
        r for _, r in prec_acc.iterrows()
        if str(r["resource_id"]).strip() in store.resource_to_user
        and str(r["resource_id"]).strip() not in assigned_acc
    ]
    cand_list = []
    for u_acc in unassigned_accs:
        acc_cand = str(u_acc["resource_id"]).strip()
        c_uid = store.resource_to_user.get(acc_cand)
        if c_uid:
            has_ana = any(r.startswith("analytics_") for r in store.user_to_resources.get(c_uid, set())) or (c_uid in sim_user_to_ana)
            if not has_ana:
                cand_list.append((acc_cand, c_uid, u_acc["dt"]))
    if cand_list:
        cand_list.sort(key=lambda x: x[2])
        chosen_acc, chosen_uid, _ = cand_list[0]
        sim_user_to_ana.setdefault(chosen_uid, []).append(ana_res)
        assigned_ana.add(ana_res)
        assigned_acc.add(chosen_acc)

print("\n--- RESULTS OF CANDIDATE LOGIC ---")
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
