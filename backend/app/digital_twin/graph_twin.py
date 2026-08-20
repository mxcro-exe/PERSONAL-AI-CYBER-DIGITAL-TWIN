"""
Personal AI Cyber Digital Twin - Attack Graph & Process Lineage Subsystem
"""

import networkx as nx
import logging
from typing import Dict, Any, List
from app.digital_twin.memory_engine import MemoryEngine

logger = logging.getLogger("CyberTwin.DigitalTwin.Graph")

class DigitalTwinGraphEngine:
    @staticmethod
    def build_endpoint_attack_graph() -> Dict[str, Any]:
        """
        Constructs a NetworkX graph representing the endpoint's process lineage, 
        socket connections, and active threat propagation paths.
        """
        G = nx.DiGraph()
        
        events = MemoryEngine.get_recent_events(limit=100)
        
        # Root Digital Twin Node
        G.add_node("HOST_ENDPOINT", label="Local Endpoint Twin", type="host", risk=0)
        
        for ev in events:
            etype = ev.get("event_type")
            raw = ev.get("raw_payload", {})
            risk = ev.get("risk_score", 0)
            
            if etype == "process":
                proc_name = raw.get("process_name", "unknown")
                pid = raw.get("pid", 0)
                parent_name = raw.get("parent_name", "system")
                
                node_id = f"proc_{pid}"
                parent_id = f"proc_parent_{parent_name}"
                
                G.add_node(node_id, label=f"{proc_name} (PID {pid})", type="process", risk=risk)
                G.add_node(parent_id, label=parent_name, type="process", risk=0)
                
                G.add_edge("HOST_ENDPOINT", parent_id, relation="HOSTS")
                G.add_edge(parent_id, node_id, relation="SPAWNED")
                
            elif etype == "network":
                remote = raw.get("remote_address", "N/A")
                pid = raw.get("pid")
                
                net_id = f"net_{remote}"
                proc_id = f"proc_{pid}" if pid else "HOST_ENDPOINT"
                
                G.add_node(net_id, label=f"Socket: {remote}", type="network", risk=risk)
                if proc_id in G:
                    G.add_edge(proc_id, net_id, relation="CONNECTED_TO")
                else:
                    G.add_edge("HOST_ENDPOINT", net_id, relation="OPENED_SOCKET")

        # Convert NetworkX graph to D3/vis.js compatible JSON format
        nodes = []
        for n, d in G.nodes(data=True):
            nodes.append({
                "id": n,
                "label": d.get("label", n),
                "type": d.get("type", "node"),
                "risk": d.get("risk", 0)
            })
            
        links = []
        for u, v, d in G.edges(data=True):
            links.append({
                "source": u,
                "target": v,
                "relation": d.get("relation", "CONNECTED")
            })
            
        return {
            "total_nodes": G.number_of_nodes(),
            "total_edges": G.number_of_edges(),
            "nodes": nodes,
            "links": links
        }
