with open("dataset/evidence/logs/resource_lookup_trace_20260926_103856.log", "r") as f:
    for line in f:
        line = line.strip()
        if "event=" in line and ("started" in line or "completed" in line) and "readback_collector" not in line:
            if "completed" in line:
                print(line)
