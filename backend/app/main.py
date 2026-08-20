"""
Personal AI Cyber Digital Twin - Main FastAPI Application Server & Background Collector Daemon
"""

import asyncio
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pathlib import Path

from app.core.config import settings
from app.core.database import init_db
from app.core.privacy import PrivacyGuard
from app.api.router import api_router

from app.collectors.process_collector import ProcessCollector
from app.collectors.network_collector import NetworkCollector
from app.collectors.clipboard_collector import ClipboardCollector
from app.collectors.device_collector import DeviceCollector
from app.collectors.fim_monitor import FileIntegrityMonitor

from app.digital_twin.behavioral_baseline import BehavioralBaselineEngine
from app.digital_twin.memory_engine import MemoryEngine

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("CyberTwin.Main")

# WebSocket Connection Manager for Live Dashboard Telemetry
class WebSocketManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"WebSocket client connected. Total clients: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info("WebSocket client disconnected.")

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.debug(f"Error broadcasting to client: {e}")

ws_manager = WebSocketManager()

# Background OS Telemetry Polling Loop
async def run_telemetry_loop():
    logger.info("Starting real-time OS telemetry background loop...")
    process_collector = ProcessCollector()
    network_collector = NetworkCollector()
    clipboard_collector = ClipboardCollector()
    device_collector = DeviceCollector()
    fim_monitor = FileIntegrityMonitor()
    baseline_engine = BehavioralBaselineEngine()
    
    while True:
        try:
            # 1. Process Collector
            proc_events = process_collector.collect_new_processes()
            for ev in proc_events:
                # Update behavioral baseline for process frequency
                pname = ev['raw_payload'].get('process_name', 'unknown')
                is_anom, z_score, _ = baseline_engine.update_and_evaluate("process_launch_frequency", pname, 1.0)
                if is_anom:
                    ev['severity'] = "high"
                    ev['risk_score'] = max(ev['risk_score'], 75)
                    
                MemoryEngine.save_event(ev)
                await ws_manager.broadcast({"type": "telemetry_event", "data": ev})

            # 2. Network Collector
            net_events = network_collector.collect_network_events()
            for ev in net_events:
                MemoryEngine.save_event(ev)
                await ws_manager.broadcast({"type": "telemetry_event", "data": ev})

            # 3. Clipboard Guard
            clip_events = clipboard_collector.collect_clipboard_events()
            for ev in clip_events:
                MemoryEngine.save_event(ev)
                await ws_manager.broadcast({"type": "telemetry_event", "data": ev})

            # 4. Device / USB Collector
            dev_events = device_collector.collect_device_events()
            for ev in dev_events:
                MemoryEngine.save_event(ev)
                await ws_manager.broadcast({"type": "telemetry_event", "data": ev})

            # 5. File Integrity Monitor (FIM) / Canary Watcher
            fim_events = fim_monitor.detect_compromise_and_auto_remediate()
            for ev in fim_events:
                MemoryEngine.save_event(ev)
                await ws_manager.broadcast({"type": "telemetry_event", "data": ev})

            # Broadcast Digital Twin health score pulse every 3 seconds
            health = MemoryEngine.calculate_twin_health()
            await ws_manager.broadcast({"type": "health_pulse", "data": health})

        except Exception as e:
            logger.error(f"Unhandled error in telemetry collection loop: {e}")
            
        await asyncio.sleep(settings.PROCESS_POLL_INTERVAL)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup tasks
    logger.info("Initializing Cyber Twin database and starting services...")
    init_db()
    telemetry_task = asyncio.create_task(run_telemetry_loop())
    yield
    # Shutdown tasks
    logger.info("Shutting down background telemetry services...")
    telemetry_task.cancel()

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.VERSION,
    lifespan=lifespan
)

# CORS middleware for web dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API Router
app.include_router(api_router, prefix="/api/v1")

# WebSocket Endpoint
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            # Echo heartbeat or client commands
            await websocket.send_json({"type": "ack", "msg": "Client heart-beat acknowledged"})
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)

# Serve Frontend Static Files
FRONTEND_DIR = Path(__file__).resolve().parent.parent.parent / "frontend"
if FRONTEND_DIR.exists():
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")
else:
    logger.error(f"Frontend directory not found at: {FRONTEND_DIR}")

