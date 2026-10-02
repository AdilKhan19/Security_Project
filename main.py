import time
import os
import shutil  # <-- Advanced library to isolate system files dynamically

TARGET_DIR = "./system_vault" 
QUARANTINE_DIR = "./quarantine_vault"  # <-- Isolated containment area

from engine import capture_baseline, load_baseline
from hasher import calculate_sha256

def quarantine_file(file_path):
    """
    Safely extracts a compromised or unknown file away from its home folder 
    and locks it down into an isolated quarantine folder.
    """
    if not os.path.exists(QUARANTINE_DIR):
        os.makedirs(QUARANTINE_DIR)
        
    file_name = os.path.basename(file_path)
    # Give the quarantined file a unique name using a timestamp
    destination_path = os.path.join(QUARANTINE_DIR, f"QUARANTINED_{time.strftime('%Y%m%d_%H%M%S')}_{file_name}")
    
    try:
        shutil.move(file_path, destination_path)
        print(f"[SYSTEM ACTION] Threat neutralized! File isolated to: {destination_path}")
    except Exception as e:
        print(f"[FAILED TO QUARANTINE] Could not relocate target: {e}")

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
                    quarantine_file(full_path)  # <-- Fire defensive response!
            else:
                print(f"[UNKNOWN ITEM] Untrusted file added to directory: {full_path}")
                quarantine_file(full_path)  # <-- Prevent rogue execution!
                
    for old_file in baseline:
        if old_file not in current_files:
            print(f"[REMOVAL ALERT] Baseline file has been deleted: {old_file}")

if __name__ == "__main__":
    if not os.path.exists(TARGET_DIR):
        os.makedirs(TARGET_DIR)
        with open(os.path.join(TARGET_DIR, "system_file.txt"), "w") as f:
            f.write("System Root Data: Safe and Secure")
            
    print("[+] Core Endpoint Monitor Engine Online.")
    while True:
        run_integrity_scan()
        time.sleep(10)