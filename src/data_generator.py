import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import random

# Configuration
NUM_LOGS = 10000
START_TIME = datetime.now() - timedelta(days=7)
USERS = [f"user_{i}" for i in range(1, 21)]
INTERNAL_IPS = [f"192.168.1.{i}" for i in range(10, 50)]
EXTERNAL_IPS = [f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}" for _ in range(50)]

EVENT_TYPES = ["LOGIN_SUCCESS", "LOGIN_FAILED", "FILE_ACCESS", "NETWORK_CONNECT", "LOGOUT", "COMMAND_EXECUTION"]

def generate_benign_logs(num_logs):
    logs = []
    current_time = START_TIME
    
    for _ in range(num_logs):
        current_time += timedelta(seconds=random.randint(1, 60))
        user = random.choice(USERS)
        src_ip = random.choice(INTERNAL_IPS)
        dest_ip = random.choice(INTERNAL_IPS + EXTERNAL_IPS)
        event = random.choice(EVENT_TYPES)
        
        msg = f"User {user} performed {event} from {src_ip} to {dest_ip}"
        
        if event == "LOGIN_FAILED":
            # Occasional benign login failure
            msg = f"Failed authentication for {user} from {src_ip}"
        elif event == "FILE_ACCESS":
            msg = f"User {user} accessed file /var/data/doc_{random.randint(1,100)}.txt"
        
        logs.append({
            "timestamp": current_time.isoformat(),
            "source_ip": src_ip,
            "dest_ip": dest_ip,
            "user": user,
            "event_type": event,
            "message": msg,
            "is_attack": 0,
            "attack_type": "None"
        })
    return logs

def inject_brute_force(logs, start_idx):
    # Brute force attack: multiple failed logins followed by a success
    attacker_ip = random.choice(EXTERNAL_IPS)
    target_user = random.choice(USERS)
    target_ip = random.choice(INTERNAL_IPS)
    
    current_time = datetime.fromisoformat(logs[start_idx]["timestamp"])
    
    attack_logs = []
    for _ in range(20):
        current_time += timedelta(seconds=random.randint(1, 3))
        attack_logs.append({
            "timestamp": current_time.isoformat(),
            "source_ip": attacker_ip,
            "dest_ip": target_ip,
            "user": target_user,
            "event_type": "LOGIN_FAILED",
            "message": f"Failed authentication for {target_user} from {attacker_ip} (Brute Force)",
            "is_attack": 1,
            "attack_type": "Brute Force"
        })
    
    # Finally succeeds
    current_time += timedelta(seconds=2)
    attack_logs.append({
        "timestamp": current_time.isoformat(),
        "source_ip": attacker_ip,
        "dest_ip": target_ip,
        "user": target_user,
        "event_type": "LOGIN_SUCCESS",
        "message": f"User {target_user} performed LOGIN_SUCCESS from {attacker_ip} to {target_ip}",
        "is_attack": 1,
        "attack_type": "Brute Force"
    })
    
    return attack_logs

def inject_lateral_movement(logs, start_idx):
    # Lateral movement: one internal IP connects to many other internal IPs rapidly
    compromised_user = random.choice(USERS)
    compromised_ip = random.choice(INTERNAL_IPS)
    
    current_time = datetime.fromisoformat(logs[start_idx]["timestamp"])
    attack_logs = []
    
    targets = random.sample(INTERNAL_IPS, 5)
    for target in targets:
        if target == compromised_ip: continue
        current_time += timedelta(seconds=random.randint(5, 15))
        attack_logs.append({
            "timestamp": current_time.isoformat(),
            "source_ip": compromised_ip,
            "dest_ip": target,
            "user": compromised_user,
            "event_type": "NETWORK_CONNECT",
            "message": f"Suspicious lateral connection from {compromised_ip} to {target}",
            "is_attack": 1,
            "attack_type": "Lateral Movement"
        })
        current_time += timedelta(seconds=2)
        attack_logs.append({
            "timestamp": current_time.isoformat(),
            "source_ip": compromised_ip,
            "dest_ip": target,
            "user": compromised_user,
            "event_type": "LOGIN_SUCCESS",
            "message": f"User {compromised_user} logged into {target} from {compromised_ip}",
            "is_attack": 1,
            "attack_type": "Lateral Movement"
        })
    return attack_logs

def generate_dataset():
    print("Generating benign logs...")
    logs = generate_benign_logs(NUM_LOGS)
    
    print("Injecting attacks...")
    # Inject Brute Force
    for _ in range(5):
        idx = random.randint(0, len(logs)-1)
        attacks = inject_brute_force(logs, idx)
        logs.extend(attacks)
        
    # Inject Lateral Movement
    for _ in range(5):
        idx = random.randint(0, len(logs)-1)
        attacks = inject_lateral_movement(logs, idx)
        logs.extend(attacks)
        
    # Sort by timestamp
    logs.sort(key=lambda x: x["timestamp"])
    
    df = pd.DataFrame(logs)
    df.to_csv("data/raw_logs.csv", index=False)
    print(f"Dataset generated with {len(df)} logs. Saved to data/raw_logs.csv")
    print("Attack distribution:")
    print(df["attack_type"].value_counts())

if __name__ == "__main__":
    import os
    os.makedirs("data", exist_ok=True)
    generate_dataset()
