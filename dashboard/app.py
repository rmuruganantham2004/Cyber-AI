import streamlit as st
import pandas as pd
import plotly.express as px
import networkx as nx
from pyvis.network import Network
import streamlit.components.v1 as components
import pickle
import os

st.set_page_config(layout="wide", page_title="AI Cyber Threat Intelligence")

st.title("🛡️ AI-Powered Cyber Threat Intelligence Dashboard")

@st.cache_data
def load_data():
    try:
        df = pd.read_csv("data/processed/final_threat_scores.csv")
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        return df
    except Exception as e:
        return None

df = load_data()

if df is None:
    st.warning("Data not found. Please run the full pipeline first.")
    st.stop()

# --- Metrics Header ---
col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Logs Processed", len(df))
col2.metric("Critical Threats", len(df[df['severity'] == 'CRITICAL']))
col3.metric("High Threats", len(df[df['severity'] == 'HIGH']))
col4.metric("Low Threats", len(df[df['severity'] == 'LOW']))

# --- Main Layout ---
tab1, tab2, tab3 = st.tabs(["Log Timeline & Anomalies", "Interaction Graph", "Raw Logs"])

with tab1:
    st.subheader("Threat Timeline")
    # Group by time
    df_time = df.set_index('timestamp').resample('H').size().reset_index(name='count')
    
    # Scatter plot for anomalies
    fig = px.scatter(
        df, x="timestamp", y="overall_risk_score", 
        color="severity",
        color_discrete_map={"CRITICAL": "red", "HIGH": "orange", "LOW": "green"},
        hover_data=["user", "source_ip", "event_type", "cleaned_message"],
        title="Anomaly Scores over Time"
    )
    st.plotly_chart(fig, use_container_width=True)
    
    st.subheader("Critical Alerts")
    st.dataframe(df[df['severity'] == 'CRITICAL'][['timestamp', 'user', 'source_ip', 'dest_ip', 'event_type', 'overall_risk_score']])

with tab2:
    st.subheader("Entity Interaction Graph")
    st.write("Visualizing relationships between Users and IPs for Critical/High logs.")
    
    try:
        with open("data/processed/interaction_graph.pkl", "rb") as f:
            G = pickle.load(f)
            
        # Filter graph to only show interactions involving critical/high nodes
        critical_users = df[df['severity'].isin(['CRITICAL', 'HIGH'])]['user'].unique()
        critical_ips = df[df['severity'].isin(['CRITICAL', 'HIGH'])]['source_ip'].unique()
        
        nodes_to_keep = set(critical_users).union(set(critical_ips))
        
        # Subgraph
        sub_g = G.subgraph(nodes_to_keep)
        
        if len(sub_g.nodes) > 0:
            net = Network(height="600px", width="100%", bgcolor="#222222", font_color="white")
            # Populate pyvis network
            for node in sub_g.nodes():
                node_type = sub_g.nodes[node].get('type', 'unknown')
                color = "red" if node in critical_users else "orange"
                net.add_node(node, label=node, color=color, title=f"Type: {node_type}")
                
            for edge in sub_g.edges():
                net.add_edge(edge[0], edge[1])
                
            net.save_graph("graph.html")
            
            with open("graph.html", 'r', encoding='utf-8') as f:
                html_data = f.read()
            components.html(html_data, height=650)
        else:
            st.info("No critical interactions to display.")
            
    except Exception as e:
        st.error(f"Error loading graph: {e}")

with tab3:
    st.subheader("Raw Processed Data")
    st.dataframe(df)
