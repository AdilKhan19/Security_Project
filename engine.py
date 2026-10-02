import os
import json
from hasher import calculate_sha256

DB_FILE = "security_baseline.json"

def capture_baseline(directory_to_watch):
    baseline = {}
    print(f"[*] Scanning {directory_to_watch} to establish secure baseline...")
    
    for root, _, files in os.walk(directory_to_watch):
        for file in files:
            full_path = os.path.join(root, file)
            file_hash = calculate_sha256(full_path)
            if file_hash:
                baseline[full_path] = file_hash
                
    with open(DB_FILE, "w") as f:
        json.dump(baseline, f, indent=4)
        
    print(f"[+] Baseline saved to {DB_FILE}. Monitored files: {len(baseline)}")
    return baseline

def load_baseline():
    if not os.path.exists(DB_FILE):
        return None
    with open(DB_FILE, "r") as f:
        return json.load(f)
