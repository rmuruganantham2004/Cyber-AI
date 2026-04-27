import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset

class AnomalyAutoencoder(nn.Module):
    def __init__(self, input_dim):
        super(AnomalyAutoencoder, self).__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 128),
            nn.ReLU(),
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Linear(64, 32)
        )
        self.decoder = nn.Sequential(
            nn.Linear(32, 64),
            nn.ReLU(),
            nn.Linear(64, 128),
            nn.ReLU(),
            nn.Linear(128, input_dim)
        )
        
    def forward(self, x):
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return decoded

class AnomalyDetector:
    def __init__(self):
        self.iso_forest = IsolationForest(contamination=0.05, random_state=42)
        self.scaler = StandardScaler()
        self.autoencoder = None
        self.device = torch.device('mps' if torch.backends.mps.is_available() else ('cuda' if torch.cuda.is_available() else 'cpu'))
        
    def prepare_features(self, df, embeddings):
        """Combine structured features and embeddings."""
        # Find all numerical columns to use as features
        numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
        
        # Remove target labels and synthetic columns we don't want the model to cheat with
        cols_to_drop = ['is_attack', 'iso_forest_anomaly', 'iso_forest_score', 
                        'autoencoder_anomaly', 'autoencoder_score', 'overall_risk_score']
        numeric_cols = [c for c in numeric_cols if c not in cols_to_drop]
        
        structured_features = df[numeric_cols].values
        
        # Combine with NLP embeddings
        combined = np.hstack([structured_features, embeddings])
        scaled = self.scaler.fit_transform(combined)
        return scaled
        
    def train_isolation_forest(self, features):
        print("Training Isolation Forest...")
        self.iso_forest.fit(features)
        
    def predict_isolation_forest(self, features):
        # returns 1 for inliers, -1 for outliers
        preds = self.iso_forest.predict(features)
        # Convert to 0 (normal), 1 (anomaly)
        anomalies = np.where(preds == -1, 1, 0)
        
        # Get anomaly scores (lower is more anomalous in sklearn, we invert it)
        scores = -self.iso_forest.score_samples(features)
        return anomalies, scores

    def train_autoencoder(self, features, epochs=10, batch_size=256):
        print(f"Training Autoencoder on {self.device}...")
        input_dim = features.shape[1]
        self.autoencoder = AnomalyAutoencoder(input_dim).to(self.device)
        
        criterion = nn.MSELoss()
        optimizer = torch.optim.Adam(self.autoencoder.parameters(), lr=1e-3)
        
        tensor_x = torch.Tensor(features)
        dataset = TensorDataset(tensor_x, tensor_x)
        dataloader = DataLoader(dataset, batch_size=batch_size, shuffle=True)
        
        self.autoencoder.train()
        for epoch in range(epochs):
            total_loss = 0
            for batch in dataloader:
                x = batch[0].to(self.device)
                optimizer.zero_grad()
                reconstructed = self.autoencoder(x)
                loss = criterion(reconstructed, x)
                loss.backward()
                optimizer.step()
                total_loss += loss.item()
            print(f"Epoch {epoch+1}/{epochs}, Loss: {total_loss/len(dataloader):.4f}")
            
    def predict_autoencoder(self, features):
        self.autoencoder.eval()
        tensor_x = torch.Tensor(features).to(self.device)
        with torch.no_grad():
            reconstructed = self.autoencoder(tensor_x)
            # Calculate MSE per sample
            mse = torch.mean((tensor_x - reconstructed) ** 2, dim=1).cpu().numpy()
            
        # Define anomaly threshold (e.g., 95th percentile of errors)
        threshold = np.percentile(mse, 95)
        anomalies = np.where(mse > threshold, 1, 0)
        return anomalies, mse

if __name__ == "__main__":
    import os
    
    # Load data
    try:
        df = pd.read_csv("data/processed/parsed_logs.csv")
        embeddings = np.load("data/processed/log_embeddings.npy")
    except FileNotFoundError:
        print("Processed data not found. Please run parser.py and nlp_processor.py.")
        exit(1)
        
    detector = AnomalyDetector()
    features = detector.prepare_features(df, embeddings)
    
    # Isolation Forest
    detector.train_isolation_forest(features)
    iso_anomalies, iso_scores = detector.predict_isolation_forest(features)
    
    # Autoencoder
    detector.train_autoencoder(features, epochs=20)
    ae_anomalies, ae_scores = detector.predict_autoencoder(features)
    
    # Save results
    df['iso_forest_anomaly'] = iso_anomalies
    df['iso_forest_score'] = iso_scores
    df['autoencoder_anomaly'] = ae_anomalies
    df['autoencoder_score'] = ae_scores
    
    df.to_csv("data/processed/anomaly_scores.csv", index=False)
    print("Saved anomaly scores to data/processed/anomaly_scores.csv")
