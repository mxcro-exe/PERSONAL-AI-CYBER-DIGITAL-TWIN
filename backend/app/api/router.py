"""
Personal AI Cyber Digital Twin - Main API Router
"""

from fastapi import APIRouter
from app.api.endpoints_dashboard import router as dashboard_router
from app.api.endpoints_telemetry import router as telemetry_router
from app.api.endpoints_incidents import router as incidents_router
from app.api.endpoints_agent import router as agent_router
from app.api.endpoints_malware import router as malware_router
from app.api.endpoints_remediation import router as remediation_router
from app.api.endpoints_graph import router as graph_router
from app.api.endpoints_simulation import router as simulation_router

api_router = APIRouter()
api_router.include_router(dashboard_router, prefix="/dashboard", tags=["Dashboard"])
api_router.include_router(telemetry_router, prefix="/telemetry", tags=["Telemetry"])
api_router.include_router(incidents_router, prefix="/incidents", tags=["Incidents"])
api_router.include_router(agent_router, prefix="/agent", tags=["AI Assistant"])
api_router.include_router(malware_router, prefix="/malware", tags=["Malware Analysis"])
api_router.include_router(remediation_router, prefix="/remediation", tags=["Remediation Playbooks"])
api_router.include_router(graph_router, prefix="/graph", tags=["Attack Graph"])
api_router.include_router(simulation_router, prefix="/simulation", tags=["Attack Simulation"])
