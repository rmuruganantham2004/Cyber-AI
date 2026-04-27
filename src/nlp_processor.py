import pandas as pd
import numpy as np
import torch
from sentence_transformers import SentenceTransformer

class NLPProcessor:
    def __init__(self, model_name='all-MiniLM-L6-v2'):
        print(f"Loading NLP Model: {model_name}...")
        # Use a lightweight model for fast embeddings
        self.device = 'mps' if torch.backends.mps.is_available() else ('cuda' if torch.cuda.is_available() else 'cpu')
        self.model = SentenceTransformer(model_name, device=self.device)
        print(f"Model loaded on {self.device}")

    def generate_embeddings(self, messages):
        """Generate BERT embeddings for a list of text messages."""
        print(f"Generating embeddings for {len(messages)} messages...")
        # Convert to list if it's a pandas Series
        if isinstance(messages, pd.Series):
            messages = messages.tolist()
            
        # Encode messages (returns numpy array)
        embeddings = self.model.encode(messages, show_progress_bar=True)
        return embeddings

    def process_dataframe(self, df, text_column='cleaned_message'):
        """Generates embeddings and attaches them to the dataframe."""
        embeddings = self.generate_embeddings(df[text_column])
        
        # We'll return the embeddings as a separate numpy array for ML,
        # but also can store them in a file
        return embeddings

if __name__ == "__main__":
    import os
    
    # Load parsed logs
    try:
        df = pd.read_csv("data/processed/parsed_logs.csv")
    except FileNotFoundError:
        print("parsed_logs.csv not found. Please run parser.py first.")
        exit(1)
        
    processor = NLPProcessor()
    embeddings = processor.process_dataframe(df)
    
    # Save embeddings
    os.makedirs("data/processed", exist_ok=True)
    np.save("data/processed/log_embeddings.npy", embeddings)
    print(f"Saved {embeddings.shape} embeddings to data/processed/log_embeddings.npy")
