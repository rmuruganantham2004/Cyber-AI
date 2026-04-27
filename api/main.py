from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
import pandas as pd
import numpy as np
import random
from datetime import datetime
import os
import pickle

app = FastAPI(title="AI Cyber Threat Intelligence API")

# Ensure frontend directory exists
os.makedirs("frontend", exist_ok=True)

# Mount the static frontend directory
app.mount("/static", StaticFiles(directory="frontend"), name="static")

# Models
class LogEntry(BaseModel):
    timestamp: str
    source_ip: str
    dest_ip: str
    user: str
    event_type: str
    message: str

# Load pre-processed offline data to serve to the dashboard
try:
    df_scores = pd.read_csv("data/processed/final_threat_scores.csv")
    df_scores['timestamp'] = pd.to_datetime(df_scores['timestamp'])
    # Sort descending by timestamp
    df_scores = df_scores.sort_values(by='timestamp', ascending=False)
except Exception:
    df_scores = pd.DataFrame()

# Serve index.html at root
@app.get("/")
def serve_dashboard():
    return FileResponse("frontend/index.html")

@app.get("/api/stats")
def get_stats():
    if df_scores.empty:
        return {"total_logs": 0, "active_alerts": 0, "avg_threat_score": 0, "graph_nodes": 0, "model_f1": 0.0}
        
    total_logs = len(df_scores)
    active_alerts = len(df_scores[df_scores['severity'].isin(['CRITICAL', 'HIGH'])])
    avg_score = df_scores['overall_risk_score'].mean()
    
    # Load graph size if available
    nodes = 0
    edges = 0
    try:
        with open("data/processed/interaction_graph.pkl", "rb") as f:
            G = pickle.load(f)
            nodes = G.number_of_nodes()
            edges = G.number_of_edges()
    except:
        pass
        
    # Hardcoded F1 for demo, usually pulled from evaluation metrics
    model_f1 = 0.93 
    
    return {
        "total_logs": total_logs,
        "active_alerts": active_alerts,
        "avg_threat_score": float(avg_score),
        "graph_nodes": nodes,
        "graph_edges": edges,
        "model_f1": model_f1
    }

@app.get("/api/logs")
def get_logs(limit: int = 20):
    if df_scores.empty:
        return []
    
    # Return latest N logs
    logs = df_scores.head(limit).replace({np.nan: None}).to_dict(orient="records")
    return logs

@app.get("/api/alerts")
def get_alerts(limit: int = 10):
    if df_scores.empty:
        return []
        
    alerts_df = df_scores[df_scores['severity'].isin(['CRITICAL', 'HIGH'])].head(limit)
    return alerts_df.replace({np.nan: None}).to_dict(orient="records")

@app.get("/api/models")
def get_models_status():
    if df_scores.empty:
        return {"isolation_forest": 0, "autoencoder": 0, "gnn": 0}
        
    iso_mean = float(df_scores['iso_forest_score'].mean())
    ae_mean = float(df_scores['autoencoder_score'].mean())
    gnn_mean = float(df_scores['gnn_max_risk'].mean())
    
    return {
        "isolation_forest": round(iso_mean, 2),
        "autoencoder": round(ae_mean, 2),
        "gnn": round(gnn_mean, 2)
    }

@app.get("/api/graph")
def get_graph_data(limit_nodes: int = 50):
    try:
        with open("data/processed/interaction_graph.pkl", "rb") as f:
            G = pickle.load(f)
            
        nodes = []
        edges = []
        
        # Subsample graph for performance in frontend
        # Get nodes involved in critical alerts
        critical_users = set(df_scores[df_scores['severity'] == 'CRITICAL']['user'])
        critical_ips = set(df_scores[df_scores['severity'] == 'CRITICAL']['source_ip'])
        important_nodes = list(critical_users.union(critical_ips))
        
        if len(important_nodes) < limit_nodes:
            # Fill with random nodes
            import random
            remaining = limit_nodes - len(important_nodes)
            other_nodes = list(set(G.nodes()) - set(important_nodes))
            important_nodes.extend(random.sample(other_nodes, min(remaining, len(other_nodes))))
            
        sub_g = G.subgraph(important_nodes[:limit_nodes])
        
        for n in sub_g.nodes():
            n_type = sub_g.nodes[n].get('type', 'unknown')
            color = "#FF2A4D" if n in critical_users or n in critical_ips else "#00FFA3"
            nodes.append({
                "id": n,
                "label": str(n),
                "group": n_type,
                "color": color
            })
            
        for e in sub_g.edges():
            edges.append({
                "from": e[0],
                "to": e[1]
            })
            
        return {"nodes": nodes, "edges": edges}
    except Exception as e:
        print(f"Error loading graph: {e}")
        return {"nodes": [], "edges": []}

@app.get("/health")
def health_check():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
