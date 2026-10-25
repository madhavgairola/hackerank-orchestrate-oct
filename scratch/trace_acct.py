import sys
sys.path.insert(0, './code')
from identity import IdentityGraph
import evidence_store
import pandas as pd

idg = IdentityGraph('dataset/user_identities.csv', 'dataset/user_audit_log.csv')
store = evidence_store.EvidenceStore('dataset', idg)

# Print who owns account_6523 and account_4092
print("account_6523 owner:", store.resource_to_user.get('account_6523'))
print("account_4092 owner:", store.resource_to_user.get('account_4092'))
