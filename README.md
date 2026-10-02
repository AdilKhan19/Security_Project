# Signature-Based Endpoint Integrity Guard (SEIG)

A modular, lightweight endpoint security engine engineered in Python. This utility actively monitors critical file systems for indicators of compromise (IoC) and unauthorized external modifications using cryptographic SHA-256 data validation and automated containment.

## System Architecture & Data Flow

```text
       [ TARGET DIR ] 
      (./system_vault)
             │
             ▼
      [ FILE READ ENGINE ] ──► (Reads file payload in tight 4KB binary blocks)
             │
             ▼
     [ CRYPTO HASHER ] ────► (Generates unique SHA-256 Signature)
             │
             ├──► [ IF NO BASELINE EXIST ] ──► Compiles registry database ──► [ security_baseline.json ]
             │
             └──► [ IF BASELINE EXISTS ] ──► Cyclic Active Patrol Logic
                                                   │
                ┌──────────────────────────────────┴──────────────────────────────────┐
                ▼                                  ▼                                  ▼
      【 Content Mismatch 】             【 Unindexed Addition 】             【 Baseline File Missing 】
        (SHA-256 Scrambled)                 (Unknown Threat)                    (Malicious Deletion)
                │                                  │                                  │
                ▼                                  ▼                                  ▼
      [ 🚨 TAMPER ALARM ]               [ ⚠️ UNKNOWN ALERT ]                [ ❌ REMOVAL ALERT ]
                │                                  │
                └─────────────────┬────────────────┘
                                  │
                                  ▼
                     [ AUTOMATED CONTAINMENT ZONE ]
                          (./quarantine_vault)
```



## Core Strategic Features

- **Data Persistence Registry:** Maps out and preserves clean directory structures inside an isolated local storage baseline configuration registry (`JSON`).
- **Cryptographic Payload Auditing:** Evaluates application layers utilizing standard **SHA-256 structures**. Files are streamed sequentially in optimized **4096-byte blocks** to enforce memory safety and eliminate processing performance spikes.
- **Defensive Threat Containment:** Intercepts real-time administrative modifications or unauthorized software injections, launching a quarantine sequence that safely strips compromised items away from protected operational volumes.


## Structural Code Manifest

```text
Security_Project/
│
├── hasher.py          # Low-level binary chunk reader and SHA-256 hashing functions
├── engine.py          # System state manager controlling baseline configurations and database syncs
├── main.py            # Main orchestrator running continuous background patrol loops and containment
└── .gitignore         # Prevents local registry logs and security test vaults from tracking leakage
```

## Deployment & System Evaluation

### 1. Clone Workspace
Clone this security framework repository infrastructure locally to your machine:
```bash
git clone https://github.com
cd Security_Project
```

### 2. Launch Endpoint Guardian
Run the core controller file to initialize your background directory scanner:
```bash
python main.py
```

### 3. Simulate Tamper Exploitation
1. Open the automatically generated security path: `./system_vault/system_file.txt`
2. Inject a random modification or rename a system file line.
3. Save the payload changes and observe your running application logs capture, alert, and neutralize the modification instantly.
