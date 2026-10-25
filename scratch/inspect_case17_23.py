import sys
sys.path.insert(0, './code')
import csv
import json
from identity import IdentityGraph

idg = IdentityGraph('dataset/user_identities.csv', 'dataset/user_audit_log.csv')
for cid, email in [('case_23', 'thandiwe.m6866@zoho.com'), ('case_17', 'leonie.g9352@outlook.com')]:
    u = idg.resolve_user(email)
    print(f"=== {cid}: {email} -> {u.user_id if u else 'None'} ===")
    if u:
        print(f"  Emails: {u.emails}")
        print(f"  Phones: {u.phones}")
    
    # Check activity for this user or email
    with open('dataset/system_activity.csv', 'r', encoding='utf-8') as f:
        for r in csv.DictReader(f):
            if (u and u.user_id in r['details']) or email in r['details'] or (u and u.user_id in r['resource_id']):
                print(f"  Activity: {r['activity_id']} {r['event_time']} {r['event_type']} {r['resource_id']} {r['details']}")
