import pandas as pd
import numpy as np

class ThreatEngine:
    def __init__(self, weight_iso=0.3, weight_ae=0.4, weight_gnn=0.3):
        self.weights = {
            'iso': weight_iso,
            'ae': weight_ae,
            'gnn': weight_gnn
        }
        
    def normalize_scores(self, series):
        """Min-Max normalization of a pandas Series."""
        return (series - series.min()) / (series.max() - series.min() + 1e-9)
        
    def calculate_risk_scores(self, df_logs, df_gnn):
        print("Calculating overall threat risk scores...")
        
        # Create a mapping for fast lookup
        gnn_scores = dict(zip(df_gnn['entity'], df_gnn['gnn_risk_score']))
        
        # Get max GNN risk among entities in each log
        def get_max_gnn_risk(row):
            user_risk = gnn_scores.get(row['user'], 0.0)
            src_risk = gnn_scores.get(row['source_ip'], 0.0)
            dest_risk = gnn_scores.get(row['dest_ip'], 0.0)
            return max(user_risk, src_risk, dest_risk)
            
        df_logs['gnn_max_risk'] = df_logs.apply(get_max_gnn_risk, axis=1)
        
        # Normalize scores
        iso_norm = self.normalize_scores(df_logs['iso_forest_score'])
        ae_norm = self.normalize_scores(df_logs['autoencoder_score'])
        gnn_norm = self.normalize_scores(df_logs['gnn_max_risk'])
        
        # Combine
        df_logs['overall_risk_score'] = (
            iso_norm * self.weights['iso'] + 
            ae_norm * self.weights['ae'] + 
            gnn_norm * self.weights['gnn']
        )
        
        # Classify severity
        conditions = [
            (df_logs['overall_risk_score'] >= 0.8),
            (df_logs['overall_risk_score'] >= 0.5),
            (df_logs['overall_risk_score'] < 0.5)
        ]
        choices = ['CRITICAL', 'HIGH', 'LOW']
        df_logs['severity'] = np.select(conditions, choices, default='LOW')
        
        return df_logs

if __name__ == "__main__":
    try:
        df_logs = pd.read_csv("data/processed/anomaly_scores.csv")
        df_gnn = pd.read_csv("data/processed/gnn_node_scores.csv")
    except FileNotFoundError:
        print("Required files not found. Run previous steps.")
        exit(1)
        
    engine = ThreatEngine()
    final_df = engine.calculate_risk_scores(df_logs, df_gnn)
    
    final_df.to_csv("data/processed/final_threat_scores.csv", index=False)
    print("Saved final threat scores to data/processed/final_threat_scores.csv")
    
    # Print summary
    print("\nThreat Summary:")
    print(final_df['severity'].value_counts())
