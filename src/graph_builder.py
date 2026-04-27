import pandas as pd
import networkx as nx
import numpy as np
import pickle

class GraphBuilder:
    def __init__(self):
        self.graph = nx.MultiDiGraph()
        
    def build_graph(self, df):
        print("Building interaction graph...")
        # Nodes: Users, Source IPs, Dest IPs
        # Edges: User -> Source IP, Source IP -> Dest IP
        
        for _, row in df.iterrows():
            user = row['user']
            src_ip = row['source_ip']
            dest_ip = row['dest_ip']
            timestamp = row['timestamp']
            event_type = row['event_type']
            
            # Add nodes
            if not self.graph.has_node(user):
                self.graph.add_node(user, type='user')
            if not self.graph.has_node(src_ip):
                self.graph.add_node(src_ip, type='ip')
            if not self.graph.has_node(dest_ip):
                self.graph.add_node(dest_ip, type='ip')
                
            # Add edges
            # User -> Source IP (Login origin)
            self.graph.add_edge(user, src_ip, 
                                timestamp=timestamp, 
                                event_type=event_type,
                                relation='login_from')
                                
            # Source IP -> Dest IP (Network connection / Interaction)
            self.graph.add_edge(src_ip, dest_ip, 
                                timestamp=timestamp, 
                                event_type=event_type,
                                user=user,
                                relation='connects_to')
                                
        print(f"Graph built with {self.graph.number_of_nodes()} nodes and {self.graph.number_of_edges()} edges.")
        return self.graph
        
    def extract_node_features(self):
        """Extract basic graph features for nodes (degree, etc) to be used by GNN."""
        # Calculate centrality
        in_degrees = dict(self.graph.in_degree())
        out_degrees = dict(self.graph.out_degree())
        
        features = {}
        for node in self.graph.nodes():
            features[node] = [
                in_degrees.get(node, 0),
                out_degrees.get(node, 0)
            ]
        return features
        
if __name__ == "__main__":
    import os
    
    try:
        df = pd.read_csv("data/processed/anomaly_scores.csv")
    except FileNotFoundError:
        print("anomaly_scores.csv not found. Please run previous steps.")
        exit(1)
        
    builder = GraphBuilder()
    G = builder.build_graph(df)
    features = builder.extract_node_features()
    
    # Save graph and features
    os.makedirs("data/processed", exist_ok=True)
    with open("data/processed/interaction_graph.pkl", "wb") as f:
        pickle.dump(G, f)
        
    with open("data/processed/graph_features.pkl", "wb") as f:
        pickle.dump(features, f)
        
    print("Saved graph and features to data/processed/")
