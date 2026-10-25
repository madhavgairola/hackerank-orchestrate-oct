import os
import sys
sys.path.insert(0, 'code')

with open('code/evidence_store.py') as f:
    src = f.read()

src = src.replace(
    'self.resource_to_user[chosen_ana] = u_owner',
    'if chosen_ana in (\"analytics_9406\", \"analytics_5335\"): print(f\"LINE 336: {chosen_ana} -> {u_owner}\")\n                    self.resource_to_user[chosen_ana] = u_owner'
).replace(
    'self.resource_to_user[ana_res] = chosen_uid',
    'if ana_res in (\"analytics_9406\", \"analytics_5335\"): print(f\"LINE 364: {ana_res} -> {chosen_uid}\")\n                    self.resource_to_user[ana_res] = chosen_uid'
)

# Execute modified source
namespace = {'__name__': '__main__'}
exec(src, namespace)

idg = namespace['IdentityGraph']('dataset/user_identities.csv', 'dataset/user_audit_log.csv')
store = namespace['EvidenceStore']('dataset', idg)
