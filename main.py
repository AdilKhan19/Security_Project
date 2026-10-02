import time
import os
from engine import capture_baseline, load_baseline
from hasher import calculate_sha256

TARGET_DIR = "./system_vault" 

def run_integrity_scan():
    baseline = load_baseline()
    if not baseline:
        baseline = capture_baseline(TARGET_DIR)
        return

    print(f"\n[*] Security scan running at {time.strftime('%H:%M:%S')}...")
    current_files = set()
    
    for root, _, files in os.walk(TARGET_DIR):
        for file in files:
            full_path = os.path.join(root, file)
            current_files.add(full_path)
            current_hash = calculate_sha256(full_path)
            
            if full_path in baseline:
                if current_hash != baseline[full_path]:
                    print(f"[TAMPER DETECTED] File modified! Signature mismatch on: {full_path}")
            else:
                print(f"[UNKNOWN ITEM] Untrusted file added to directory: {full_path}")
                
    for old_file in baseline:
        if old_file not in current_files:
            print(f"[REMOVAL ALERT] Baseline file has been deleted: {old_file}")

# Everything below this line must be indented with 4 spaces or 1 tab!
if __name__ == "__main__":
    if not os.path.exists(TARGET_DIR):
        os.makedirs(TARGET_DIR)
        with open(os.path.join(TARGET_DIR, "system_file.txt"), "w") as f:
            f.write("System Root Data: Safe and Secure")
            
    print("[+] Core Endpoint Monitor Engine Online.")
    while True:
        run_integrity_scan()
        time.sleep(10)