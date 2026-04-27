import torch
import torch.nn.functional as F
from torch_geometric.nn import GCNConv
from torch_geometric.data import Data
import networkx as nx
import pandas as pd
import numpy as np
import pickle

class ThreatGCN(torch.nn.Module):
    def __init__(self, num_node_features, hidden_channels):
        super(ThreatGCN, self).__init__()
        self.conv1 = GCNConv(num_node_features, hidden_channels)
        self.conv2 = GCNConv(hidden_channels, 2) # Binary classification: Benign vs Threat

    def forward(self, x, edge_index):
        x = self.conv1(x, edge_index)
        x = F.relu(x)
        x = F.dropout(x, p=0.5, training=self.training)
        x = self.conv2(x, edge_index)
        return x

class GNNModel:
    def __init__(self):
        self.device = torch.device('mps' if torch.backends.mps.is_available() else ('cuda' if torch.cuda.is_available() else 'cpu'))
        self.model = None
        
    def prepare_data(self, nx_graph, node_features_dict, df):
        """Convert NetworkX graph to PyTorch Geometric Data object."""
        print("Preparing graph data for GNN...")
        
        # Create a mapping from node name to integer ID
        node_mapping = {node: i for i, node in enumerate(nx_graph.nodes())}
        num_nodes = len(node_mapping)
        
        # Determine labels for nodes based on log ground truth
        # If a node was involved in an attack log, mark it as 1 (threat)
        node_labels = np.zeros(num_nodes, dtype=np.int64)
        attack_logs = df[df['is_attack'] == 1]
        
        for _, row in attack_logs.iterrows():
            if row['user'] in node_mapping:
                node_labels[node_mapping[row['user']]] = 1
            if row['source_ip'] in node_mapping:
                node_labels[node_mapping[row['source_ip']]] = 1
            if row['dest_ip'] in node_mapping:
                node_labels[node_mapping[row['dest_ip']]] = 1
                
        # Prepare edge index
        edge_index = []
        for u, v in nx_graph.edges():
            edge_index.append([node_mapping[u], node_mapping[v]])
        edge_index = torch.tensor(edge_index, dtype=torch.long).t().contiguous()
        
        # Prepare node features
        # Add basic features + a 1-hot encoding of whether it's a user or IP
        x_features = []
        for node in nx_graph.nodes():
            base_feat = node_features_dict[node]
            node_type = nx_graph.nodes[node].get('type', 'unknown')
            type_feat = [1, 0] if node_type == 'user' else [0, 1]
            x_features.append(base_feat + type_feat)
            
        x = torch.tensor(x_features, dtype=torch.float)
        y = torch.tensor(node_labels, dtype=torch.long)
        
        # Create masks for train/test (80/20 split)
        indices = np.arange(num_nodes)
        np.random.shuffle(indices)
        train_idx = indices[:int(0.8 * num_nodes)]
        test_idx = indices[int(0.8 * num_nodes):]
        
        train_mask = torch.zeros(num_nodes, dtype=torch.bool)
        test_mask = torch.zeros(num_nodes, dtype=torch.bool)
        train_mask[train_idx] = True
        test_mask[test_idx] = True
        
        data = Data(x=x, edge_index=edge_index, y=y, 
                    train_mask=train_mask, test_mask=test_mask)
                    
        return data, node_mapping

    def train(self, data, epochs=100):
        print(f"Training GNN on {self.device}...")
        self.model = ThreatGCN(num_node_features=data.num_node_features, hidden_channels=16)
        self.model = self.model.to(self.device)
        data = data.to(self.device)
        
        optimizer = torch.optim.Adam(self.model.parameters(), lr=0.01, weight_decay=5e-4)
        criterion = torch.nn.CrossEntropyLoss()
        
        self.model.train()
        for epoch in range(epochs):
            optimizer.zero_grad()
            out = self.model(data.x, data.edge_index)
            loss = criterion(out[data.train_mask], data.y[data.train_mask])
            loss.backward()
            optimizer.step()
            
            if (epoch+1) % 20 == 0:
                print(f"Epoch {epoch+1:03d}, Loss: {loss.item():.4f}")
                
    def evaluate(self, data):
        self.model.eval()
        data = data.to(self.device)
        out = self.model(data.x, data.edge_index)
        pred = out.argmax(dim=1)
        
        test_correct = pred[data.test_mask] == data.y[data.test_mask]
        test_acc = int(test_correct.sum()) / int(data.test_mask.sum())
        print(f"GNN Test Accuracy: {test_acc:.4f}")
        
        # Get probability scores for all nodes
        probs = F.softmax(out, dim=1)[:, 1].detach().cpu().numpy()
        return probs

if __name__ == "__main__":
    import os
    try:
        df = pd.read_csv("data/processed/anomaly_scores.csv")
        with open("data/processed/interaction_graph.pkl", "rb") as f:
            nx_graph = pickle.load(f)
        with open("data/processed/graph_features.pkl", "rb") as f:
            node_features = pickle.load(f)
    except FileNotFoundError:
        print("Data files not found. Run previous steps.")
        exit(1)
        
    gnn = GNNModel()
    data, node_mapping = gnn.prepare_data(nx_graph, node_features, df)
    
    gnn.train(data, epochs=100)
    node_risk_scores = gnn.evaluate(data)
    
    # Save GNN risk scores
    results = []
    for node, idx in node_mapping.items():
        results.append({
            "entity": node,
            "gnn_risk_score": node_risk_scores[idx]
        })
        
    res_df = pd.DataFrame(results)
    res_df.to_csv("data/processed/gnn_node_scores.csv", index=False)
    print("Saved GNN node risk scores to data/processed/gnn_node_scores.csv")
