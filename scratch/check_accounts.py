import pandas as pd
import csv
import sys
sys.path.insert(0, './code')
from identity import IdentityGraph
from evidence_store import EvidenceStore

idg = IdentityGraph('dataset/user_identities.csv', 'dataset/user_audit_log.csv')
store = EvidenceStore('dataset', idg)

print("Checking accounts for 2026-08-30:")
for acc in ['account_5482', 'account_3866', 'account_7012']:
    print(f"  {acc} -> user: {store.resource_to_user.get(acc)}")

print("\nChecking accounts for 2026-09-02:")
for acc in ['account_3136', 'account_4842', 'account_5334', 'account_5684', 'account_7225']:
    print(f"  {acc} -> user: {store.resource_to_user.get(acc)}")
