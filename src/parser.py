import pandas as pd
import numpy as np
import os
import random
from datetime import datetime, timedelta
from sklearn.preprocessing import LabelEncoder
import re

class CICIDSParser:
    def __init__(self, data_dir):
        self.data_dir = data_dir
        self.label_encoders = {}
        
    def load_and_sample(self):
        print(f"Scanning directory: {self.data_dir}")
        csv_files = [f for f in os.listdir(self.data_dir) if f.endswith('.csv')]
        
        sampled_dfs = []
        # Sample ~10k rows from each file to keep it manageable and balanced
        for file in csv_files:
            filepath = os.path.join(self.data_dir, file)
            print(f"Loading sample from {file}...")
            try:
                # Use pandas to read a sample (skiprows randomly or just take first N)
                # To get a good mix, we take the first 15,000 rows
                df = pd.read_csv(filepath, nrows=15000)
                sampled_dfs.append(df)
            except Exception as e:
                print(f"Error loading {file}: {e}")
                
        df_combined = pd.concat(sampled_dfs, ignore_index=True)
        
        # Clean column names (strip leading/trailing spaces)
        df_combined.columns = df_combined.columns.str.strip()
        print(f"Combined shape: {df_combined.shape}")
        
        # Clean labels (sometimes they have trailing spaces)
        df_combined['Label'] = df_combined['Label'].str.strip()
        print("Label Distribution:")
        print(df_combined['Label'].value_counts())
        
        return df_combined
        
    def generate_synthetic_features(self, df):
        print("Generating synthetic IPs, Users, and Messages...")
        n_rows = len(df)
        
        # We'll create a small pool of users and IPs
        users = [f"user_{i}" for i in range(1, 50)]
        internal_ips = [f"192.168.1.{i}" for i in range(10, 200)]
        external_ips = [f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}" for _ in range(500)]
        
        # Fast way to assign random values
        df['user'] = np.random.choice(users, n_rows)
        
        # If it's BENIGN, usually internal -> external or internal -> internal
        # If it's an attack, usually external -> internal
        df['is_attack'] = (df['Label'] != 'BENIGN').astype(int)
        
        src_ips = []
        dest_ips = []
        for is_atk in df['is_attack']:
            if is_atk:
                src_ips.append(random.choice(external_ips))
                dest_ips.append(random.choice(internal_ips))
            else:
                src_ips.append(random.choice(internal_ips))
                dest_ips.append(random.choice(internal_ips + external_ips))
                
        df['source_ip'] = src_ips
        df['dest_ip'] = dest_ips
        
        # Generate timestamps
        start_time = datetime.now() - timedelta(days=7)
        # Sequential timestamps
        df['timestamp'] = [start_time + timedelta(seconds=i*2) for i in range(n_rows)]
        df['timestamp'] = df['timestamp'].apply(lambda x: x.isoformat())
        
        # Generate synthetic text messages for NLP
        def make_message(row):
            return (f"Flow to port {row.get('Destination Port', 'unknown')} "
                    f"duration {row.get('Flow Duration', 0)}ms "
                    f"forward packets {row.get('Total Fwd Packets', 0)} "
                    f"backward packets {row.get('Total Backward Packets', 0)}. "
                    f"Classified as {row['Label']}.")
                    
        df['cleaned_message'] = df.apply(make_message, axis=1)
        
        # Map Label to event_type
        df['event_type'] = df['Label']
        return df

    def preprocess(self, df):
        print("Preprocessing features...")
        
        # Encode categorical
        categorical_cols = ['event_type', 'source_ip', 'dest_ip', 'user']
        for col in categorical_cols:
            le = LabelEncoder()
            df[f'{col}_encoded'] = le.fit_transform(df[col].astype(str))
            self.label_encoders[col] = le
            
        # Replace Inf and NaN in numerical columns
        numerical_cols = df.select_dtypes(include=[np.number]).columns
        df[numerical_cols] = df[numerical_cols].replace([np.inf, -np.inf], np.nan)
        df[numerical_cols] = df[numerical_cols].fillna(0)
        
        print("Preprocessing complete.")
        return df

if __name__ == "__main__":
    import os
    
    data_dir = "/Users/murugananthamr/Downloads/archive (3) 3"
    parser = CICIDSParser(data_dir)
    
    df = parser.load_and_sample()
    df = parser.generate_synthetic_features(df)
    df_processed = parser.preprocess(df)
    
    os.makedirs("data/processed", exist_ok=True)
    df_processed.to_csv("data/processed/parsed_logs.csv", index=False)
    print("Saved processed logs to data/processed/parsed_logs.csv")
