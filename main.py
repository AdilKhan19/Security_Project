import time
import os
import shutil

from engine import capture_baseline, load_baseline
from hasher import calculate_sha256

# Configuration Globals
QUARANTINE_DIR = "./quarantine_vault"

def quarantine_file(file_path):
    """Safely isolates an altered or untrusted file into a lockdown folder."""
    if not os.path.exists(QUARANTINE_DIR):
        os.makedirs(QUARANTINE_DIR)
        
    file_name = os.path.basename(file_path)
    # This gives the quarantined file a unique name, using a timestamp.
    destination_path = os.path.join(QUARANTINE_DIR, f"QUARANTINED_{time.strftime('%Y%m%d_%H%M%S')}_{file_name}")
    
    try:
        shutil.move(file_path, destination_path)
        print(f"[SYSTEM ACTION] Threat isolated safely to: {destination_path}")
    except Exception as e:
        print(f"[FAILED TO QUARANTINE] Could not move file: {e}")

def run_integrity_scan(target_directory):
    """
    Performs an integrity check on the specified directory.
    Notice how target_directory is now passed as a parameter instead of being hardcoded!
    """
    baseline = load_baseline()
    if not baseline:
        print("[NO BASELINE FOUND] Generating a new trusted baseline first...")
        capture_baseline(target_directory)
        return

    print(f"\n[*] Patrol cycle running on '{target_directory}' at {time.strftime('%H:%M:%S')}...")
    current_files = set()
    
    for root, _, files in os.walk(target_directory):
        for file in files:
            full_path = os.path.join(root, file)
            current_files.add(full_path)
            current_hash = calculate_sha256(full_path)
            
            if full_path in baseline:
                if current_hash != baseline[full_path]:
                    print(f"[TAMPER DETECTED] File modified! Mismatch on: {full_path}")
                    quarantine_file(full_path)
            else:
                print(f"[UNKNOWN ITEM] Untrusted file added: {full_path}")
                quarantine_file(full_path)
                
    for old_file in baseline:
        if old_file not in current_files and os.path.exists(old_file) == False:
            # Avoid flagging files inside the quarantine directory if it happens to sit inside the target
            if not old_file.startswith(QUARANTINE_DIR):
                print(f"[REMOVAL ALERT] Baseline file has been deleted: {old_file}")

def display_menu():
    """Prints a clean, professional dashboard interface."""
    print("\n" + "="*50)
    print("   ENDPOINT INTEGRITY DETECTOR MAIN DASHBOARD   ")
    print("="*50)
    print(" [1] Establish/Update Clean Security Baseline")
    print(" [2] Launch Continuous Background Patrol Loop")
    print(" [3] View Current Quarantined Threats Log")
    print(" [4] Exit Security Engine")
    print("="*50)

if __name__ == "__main__":
    print("[+] Core Endpoint Security Engine Online.")
    
    # Dynamically asking the user that which path would they like to protect
    target_dir = input("[INPUT REQUIRED] Enter the folder path to protect (e.g., ./system_vault): ").strip()
    
    # If the user enters a folder that doesn't exist, create it and seed it with a safe file
    if not os.path.exists(target_dir):
        os.makedirs(target_dir)
        with open(os.path.join(target_dir, "system_file.txt"), "w") as f:
            f.write("System Root Data: Safe and Secure")
        print(f"[+] Created default folder framework at '{target_dir}'.")

    # Main Interactive Runtime Loop
    while True:
        display_menu()
        choice = input("Select an option (1-4): ").strip()
        
        if choice == "1":
            capture_baseline(target_dir)
            
        elif choice == "2":
            print(f"\n[MONITOR] Patrolling '{target_dir}' every 10s. Press Ctrl+C to stop patrol and return to menu.")
            try:
                while True:
                    run_integrity_scan(target_dir)
                    time.sleep(10)
            except KeyboardInterrupt:
                print("\n[-] Background patrol paused. Returning to Dashboard...")
                
        elif choice == "3":
            print(f"\n[QUARANTINE VAULT]: {QUARANTINE_DIR}")
            if os.path.exists(QUARANTINE_DIR) and os.listdir(QUARANTINE_DIR):
                for index, item in enumerate(os.listdir(QUARANTINE_DIR), start=1):
                    print(f"  [{index}] {item}")
            else:
                print("  (Vault clean. No records logged.)")
                
        elif choice == "4":
            print("[+] Shutting down systems gracefully. Goodbye!")
            break
            
        else:
            print("[INVALID CHOICE] Input an option from 1 to 4.")
