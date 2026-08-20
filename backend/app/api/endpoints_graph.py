"""
Personal AI Cyber Digital Twin - API Endpoints: Attack Graph & Lineage
"""

from fastapi import APIRouter
from app.digital_twin.graph_twin import DigitalTwinGraphEngine

router = APIRouter()

@router.get("/attack-graph")
def get_attack_graph():
    """Generates NetworkX process lineage and socket connection attack graph."""
    return DigitalTwinGraphEngine.build_endpoint_attack_graph()
