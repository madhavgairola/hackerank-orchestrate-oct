import pandas as pd
import csv

df = pd.read_csv('dataset/system_activity.csv')
del_workers = df[df["source_system"] == "deletion_worker"].copy()
del_workers["dt"] = pd.to_datetime(del_workers["event_time"])
del_workers = del_workers.sort_values("dt")
dw_ana = del_workers[del_workers["target_system"] == "analytics_platform"]

print("All deletion_worker analytics_platform events:")
for _, r in dw_ana.iterrows():
    print(r['activity_id'], r['event_time'], r['event_type'], r['resource_id'], r['reported_result'])
