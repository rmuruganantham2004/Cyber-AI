# 🛡️ AI-Powered Cyber Threat Intelligence System

An advanced, end-to-end cybersecurity threat intelligence platform that leverages **Natural Language Processing (NLP)**, **Machine Learning Anomaly Detection**, and **Graph Neural Networks (GNN)** to process large-scale network flow data, identify potential cyber threats, and visualize entity interactions in real-time.

## ✨ Features
- **Real-World Data Processing:** Custom parsers capable of safely ingesting and sampling gigabytes of the CIC-IDS-2017 network intrusion dataset.
- **NLP Log Encoding:** Uses Hugging Face's `sentence-transformers` (`all-MiniLM-L6-v2`) to convert synthetic flow descriptions into 384-dimensional dense semantic embeddings.
- **Deep Anomaly Ensemble:** Combines an **Isolation Forest** with a PyTorch **Deep Autoencoder** to identify statistical deviations across 78+ numerical flow features and NLP embeddings.
- **Graph Neural Network (GNN):** Builds an Entity Relationship Network using `NetworkX` and classifies potentially compromised IPs/Users using a Graph Convolutional Network via `PyTorch Geometric`.
- **Real-Time API Engine:** A lightning-fast **FastAPI** backend that calculates unified threat scores and exposes JSON endpoints for live polling.
- **Premium Hacker Dashboard:** A fully custom Vanilla HTML/CSS/JS frontend featuring a dark "cyberpunk" aesthetic, dynamic DOM updates, and an interactive `vis.js` knowledge graph.

## 🏗️ System Architecture

```text
Cyber-AI/
├── data/                  # (Gitignored) Raw CIC-IDS CSVs and processed embeddings/graphs
├── src/
│   ├── parser.py          # Loads CIC-IDS, generates synthetic labels/IPs for GNN
│   ├── nlp_processor.py   # Computes BERT embeddings for flow payloads
│   ├── anomaly_detector.py# Trains Isolation Forest & Autoencoder on 78+ flow features
│   ├── graph_builder.py   # Constructs the IP/User interaction graph
│   ├── gnn_model.py       # Trains PyTorch Geometric GCN for node risk classification
│   ├── threat_engine.py   # Aggregates scores -> OVERALL_RISK (LOW, HIGH, CRITICAL)
│   └── alert_system.py    # Notification engine for critical events
├── frontend/
│   ├── index.html         # Custom semantic CSS Grid layout
│   ├── styles.css         # Premium dark mode design tokens & CSS variables
│   └── app.js             # Vanilla JS for API polling and Vis.js graph rendering
├── api/
│   └── main.py            # FastAPI server (serves frontend + REST API)
├── run_pipeline.py        # Master script to execute the offline training pipeline
└── requirements.txt       # Python dependencies
```

## 🚀 Getting Started

### Prerequisites
- Python 3.10+
- [CIC-IDS-2017 Dataset](https://www.unb.ca/cic/datasets/ids-2017.html) (Download the MachineLearningCSV zip and place the CSVs inside the `data/raw/` directory or adjust the path in `src/parser.py`).

### Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/rmuruganantham2004/Cyber-AI.git
   cd Cyber-AI
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### Running the Pipeline
Run the master pipeline script to crunch the data, generate embeddings, and train the models offline:
```bash
python run_pipeline.py
```
*(Note: This process may take a few minutes depending on your hardware, as it processes 120,000+ flows and trains deep learning models).*

### Launching the Dashboard
Once the offline pipeline completes, spin up the FastAPI server to serve the real-time dashboard:
```bash
uvicorn api.main:app --host 0.0.0.0 --port 8000
```
Open your browser and navigate to: **http://localhost:8000**

## 📊 Dashboard Visualizations
The frontend continuously polls the FastAPI backend to provide:
- **Live Log Stream:** Real-time feed of network events with associated threat scores.
- **Model Telemetry:** Live progress bars tracking Isolation Forest and Autoencoder precision metrics.
- **Knowledge Graph:** An interactive, physics-based network rendering of attacker, target, and pivot IP entities.
