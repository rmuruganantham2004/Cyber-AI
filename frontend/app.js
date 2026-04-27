// Helper to format time
function formatTime(isoString) {
    const d = new Date(isoString);
    return d.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

// Clock
setInterval(() => {
    document.getElementById('clock').textContent = formatTime(new Date().toISOString());
}, 1000);

// Fetchers
async function fetchStats() {
    try {
        const res = await fetch('/api/stats');
        const data = await res.json();
        
        document.getElementById('val-total-logs').textContent = data.total_logs.toLocaleString();
        document.getElementById('val-active-alerts').textContent = data.active_alerts.toLocaleString();
        document.getElementById('val-threat-score').textContent = data.avg_threat_score.toFixed(2);
        document.getElementById('val-graph-nodes').textContent = data.graph_nodes.toLocaleString();
        document.getElementById('val-graph-edges').textContent = data.graph_edges.toLocaleString();
        document.getElementById('val-model-f1').textContent = data.model_f1.toFixed(2);
        
        document.getElementById('badge-active-alerts').textContent = `${data.active_alerts} ACTIVE`;
    } catch (e) { console.error("Error fetching stats:", e); }
}

async function fetchModels() {
    try {
        const res = await fetch('/api/models');
        const data = await res.json();
        
        document.getElementById('score-iso').textContent = data.isolation_forest.toFixed(2);
        document.getElementById('score-ae').textContent = data.autoencoder.toFixed(2);
        document.getElementById('score-gnn').textContent = data.gnn.toFixed(2);
        
        // Update bars
        document.querySelector('#score-iso + .model-bar .fill').style.width = `${Math.min(data.isolation_forest * 100, 100)}%`;
        document.querySelector('#score-ae + .model-bar .fill').style.width = `${Math.min(data.autoencoder * 100, 100)}%`;
        document.querySelector('#score-gnn + .model-bar .fill').style.width = `${Math.min(data.gnn * 100, 100)}%`;
    } catch (e) { console.error("Error fetching models:", e); }
}

async function fetchLogs() {
    try {
        const res = await fetch('/api/logs?limit=10');
        const logs = await res.json();
        
        const container = document.getElementById('log-stream');
        container.innerHTML = '';
        
        logs.forEach(log => {
            const div = document.createElement('div');
            div.className = 'log-entry';
            
            const scoreClass = log.severity === 'CRITICAL' ? 'red' : (log.severity === 'HIGH' ? 'orange' : 'green');
            
            div.innerHTML = `
                <div class="log-time">${formatTime(log.timestamp)}</div>
                <div class="log-ip">${log.source_ip}</div>
                <div class="log-msg">${log.event_type} - ${log.cleaned_message}</div>
                <div class="log-score ${scoreClass}">[${parseFloat(log.overall_risk_score).toFixed(2)}]</div>
            `;
            container.appendChild(div);
        });
        
        // Update NLP panel with latest message
        if (logs.length > 0) {
            const latest = logs[0];
            document.getElementById('nlp-stream').innerHTML = `
                <div style="color: var(--neon-green); margin-bottom: 5px;">> Extracting entities from flow payload...</div>
                <div style="color: var(--text-bright);">> src_ip: <span class="blue">${latest.source_ip}</span></div>
                <div style="color: var(--text-bright);">> dest_ip: <span class="blue">${latest.dest_ip}</span></div>
                <div style="color: var(--text-bright);">> classification: <span class="orange">${latest.event_type}</span></div>
                <div style="color: var(--text-bright); margin-top: 5px; opacity: 0.7;">Vector embedding computed: [0.12, -0.45, 0.89, ...]</div>
            `;
        }
        
    } catch (e) { console.error("Error fetching logs:", e); }
}

async function fetchAlerts() {
    try {
        const res = await fetch('/api/alerts?limit=5');
        const alerts = await res.json();
        
        const container = document.getElementById('alerts-stream');
        if (alerts.length === 0) {
            container.innerHTML = `<div class="dim-text">No alerts yet</div>`;
            return;
        }
        
        container.innerHTML = '';
        alerts.forEach(alert => {
            const div = document.createElement('div');
            div.className = 'alert-entry';
            
            div.innerHTML = `
                <div class="alert-title">THREAT DETECTED: ${alert.event_type}</div>
                <div><span class="dim-text">Time:</span> ${formatTime(alert.timestamp)}</div>
                <div><span class="dim-text">Source:</span> ${alert.source_ip}</div>
                <div><span class="dim-text">Target:</span> ${alert.dest_ip}</div>
                <div style="margin-top: 4px;">Risk Score: <span class="red">${parseFloat(alert.overall_risk_score).toFixed(2)}</span></div>
            `;
            container.appendChild(div);
        });
        
    } catch (e) { console.error("Error fetching alerts:", e); }
}

let network = null;
async function fetchAndRenderGraph() {
    try {
        const res = await fetch('/api/graph?limit_nodes=50');
        const data = await res.json();
        
        if (data.nodes.length === 0) return;
        
        const container = document.getElementById('network-graph');
        
        const nodes = new vis.DataSet(data.nodes);
        const edges = new vis.DataSet(data.edges);
        
        const options = {
            nodes: {
                shape: 'dot',
                size: 8,
                font: { color: '#a3c2cf', size: 10, face: 'Fira Code' },
                borderWidth: 0
            },
            edges: {
                color: { color: 'rgba(92, 126, 143, 0.3)', highlight: '#00e5ff' },
                width: 1,
                smooth: { type: 'continuous' }
            },
            physics: {
                forceAtlas2Based: {
                    gravitationalConstant: -26,
                    centralGravity: 0.005,
                    springLength: 230,
                    springConstant: 0.18
                },
                maxVelocity: 146,
                solver: 'forceAtlas2Based',
                timestep: 0.35,
                stabilization: { iterations: 150 }
            },
            interaction: {
                hover: true,
                tooltipDelay: 200
            }
        };
        
        if (!network) {
            network = new vis.Network(container, { nodes, edges }, options);
        } else {
            network.setData({ nodes, edges });
        }
    } catch (e) { console.error("Error fetching graph:", e); }
}

// Initial fetch
function init() {
    fetchStats();
    fetchModels();
    fetchLogs();
    fetchAlerts();
    fetchAndRenderGraph();
    
    // Poll every 5 seconds
    setInterval(() => {
        fetchStats();
        fetchModels();
        fetchLogs();
        fetchAlerts();
    }, 5000);
    
    // Graph updates less frequently
    setInterval(() => {
        fetchAndRenderGraph();
    }, 30000);
}

document.addEventListener('DOMContentLoaded', init);
