// ============================================================
// NETLIFY STATIC DEMO MODE
// Mock data engine — replaces real backend API calls
// ============================================================

const DEMO_MODE = true;

// ---- Mock Event Feed ----
const MOCK_EVENTS = [
  { id: "ev-001", event_type: "process", severity: "medium", risk_score: 55, mitre_technique: "T1059.001 - PowerShell Execution", raw_payload: { pid: 4821, process_name: "powershell.exe", parent_name: "explorer.exe", cmdline: "powershell.exe -NoProfile -ExecutionPolicy Bypass" }, source_component: "ProcessCollector", created_at: new Date(Date.now() - 5000).toISOString() },
  { id: "ev-002", event_type: "clipboard", severity: "info", risk_score: 5, mitre_technique: null, raw_payload: { length: 32, preview: "Meeting notes - project deadline...", detected_protection: "Cleartext Clipboard Copy" }, source_component: "ClipboardCollector", created_at: new Date(Date.now() - 12000).toISOString() },
  { id: "ev-003", event_type: "network", severity: "high", risk_score: 78, mitre_technique: "T1071 - Application Layer Protocol", raw_payload: { remote_ip: "185.234.219.7", remote_port: 4444, local_port: 52371, protocol: "TCP", process_name: "python.exe", status: "ESTABLISHED" }, source_component: "NetworkCollector", created_at: new Date(Date.now() - 22000).toISOString() },
  { id: "ev-004", event_type: "usb", severity: "medium", risk_score: 45, mitre_technique: "T1091 - Replication Through Removable Media", raw_payload: { device_type: "Mass Storage", vendor: "SanDisk Corp.", description: "USB 3.0 Flash Drive (32GB)", action: "connected" }, source_component: "DeviceCollector", created_at: new Date(Date.now() - 35000).toISOString() },
  { id: "ev-005", event_type: "process", severity: "critical", risk_score: 92, mitre_technique: "T1486 - Data Encrypted for Impact (Canary File Modified)", raw_payload: { filename: "passwords_vault.txt", suspect_process: "notepad.exe", suspect_pid: 7240, action_taken: "Auto-Remediated: Terminated PID 7240" }, source_component: "FIMMonitor", created_at: new Date(Date.now() - 48000).toISOString() },
  { id: "ev-006", event_type: "clipboard", severity: "medium", risk_score: 60, mitre_technique: "T1115 - Clipboard Data", raw_payload: { length: 28, preview: "password: [REDACTED_SECRET]", detected_protection: "Sensitive Clipboard Content Blocked" }, source_component: "ClipboardCollector", created_at: new Date(Date.now() - 60000).toISOString() },
  { id: "ev-007", event_type: "process", severity: "info", risk_score: 10, mitre_technique: null, raw_payload: { pid: 9910, process_name: "chrome.exe", parent_name: "explorer.exe", cmdline: "chrome.exe --new-window" }, source_component: "ProcessCollector", created_at: new Date(Date.now() - 75000).toISOString() },
  { id: "ev-008", event_type: "network", severity: "info", risk_score: 8, mitre_technique: null, raw_payload: { remote_ip: "142.250.77.78", remote_port: 443, local_port: 55200, protocol: "TCP", process_name: "chrome.exe", status: "ESTABLISHED" }, source_component: "NetworkCollector", created_at: new Date(Date.now() - 90000).toISOString() },
];

const MOCK_INCIDENTS = [
  { id: "inc-001", title: "Canary File Ransomware Trigger Detected & Blocked", severity: "critical", risk_score: 92, mitre_technique: "T1486", status: "RESOLVED", created_at: new Date(Date.now() - 48000).toISOString() },
  { id: "inc-002", title: "Suspicious PowerShell Execution with Bypass Policy", severity: "high", risk_score: 78, mitre_technique: "T1059.001", status: "INVESTIGATING", created_at: new Date(Date.now() - 120000).toISOString() },
  { id: "inc-003", title: "Outbound C2 Beacon Detected on Port 4444", severity: "high", risk_score: 82, mitre_technique: "T1071", status: "OPEN", created_at: new Date(Date.now() - 200000).toISOString() },
  { id: "inc-004", title: "Sensitive Password Data Copied to Clipboard", severity: "medium", risk_score: 60, mitre_technique: "T1115", status: "RESOLVED", created_at: new Date(Date.now() - 250000).toISOString() },
];

const MOCK_HEALTH = { health_score: 72, status: "MODERATE RISK", active_threats: 2, total_events_24h: 47, sensors_active: 6 };

// ---- Demo Attack Graph Nodes ----
const MOCK_GRAPH = {
  nodes: [
    { id: "host", label: "Your Laptop", type: "host", risk: 72 },
    { id: "proc1", label: "powershell.exe", type: "process", risk: 78 },
    { id: "proc2", label: "chrome.exe", type: "process", risk: 10 },
    { id: "proc3", label: "python.exe", type: "process", risk: 85 },
    { id: "ip1", label: "185.234.219.7", type: "remote_ip", risk: 90 },
    { id: "ip2", label: "142.250.77.78", type: "remote_ip", risk: 5 },
    { id: "canary", label: "passwords_vault.txt", type: "file", risk: 92 },
  ],
  links: [
    { source: "host", target: "proc1" },
    { source: "host", target: "proc2" },
    { source: "host", target: "proc3" },
    { source: "proc3", target: "ip1" },
    { source: "proc2", target: "ip2" },
    { source: "proc1", target: "canary" },
  ]
};

// ---- Override API/WebSocket calls with mock data ----
function initWebSocket() {
  // Show as connected
  const statusEl = document.getElementById("connection-status");
  if (statusEl) statusEl.textContent = "DEMO MODE ACTIVE";
  
  // Load initial mock events
  MOCK_EVENTS.forEach((ev, i) => {
    setTimeout(() => prependTelemetryEvent(ev), i * 350);
  });

  // Simulate live telemetry every 5 seconds
  setInterval(() => {
    const randomEv = MOCK_EVENTS[Math.floor(Math.random() * MOCK_EVENTS.length)];
    const liveEv = { ...randomEv, id: "ev-live-" + Date.now(), created_at: new Date().toISOString() };
    prependTelemetryEvent(liveEv);

    if (liveEv.source_component === "FIMMonitor") {
      animateCanaryAlert(liveEv.raw_payload);
    }
  }, 5000);

  // Health pulse every 3 seconds with slight variation
  setInterval(() => {
    const score = MOCK_HEALTH.health_score + Math.floor(Math.random() * 6 - 3);
    updateTwinMeter({ ...MOCK_HEALTH, health_score: Math.max(0, Math.min(100, score)) });
  }, 3000);

  updateTwinMeter(MOCK_HEALTH);
}

async function loadRecentEvents() {
  MOCK_EVENTS.slice(0, 5).forEach((ev, i) => {
    setTimeout(() => prependTelemetryEvent(ev), i * 200);
  });
}

async function loadIncidents() {
  const container = document.getElementById("incidents-list");
  if (!container) return;
  container.innerHTML = "";
  MOCK_INCIDENTS.forEach(inc => {
    const div = document.createElement("div");
    div.className = `event-item ${inc.severity}`;
    div.innerHTML = `
      <div style="width:100%">
        <div class="event-meta">
          <span class="event-type">${inc.severity.toUpperCase()}</span>
          <span class="event-time">${new Date(inc.created_at).toLocaleTimeString()}</span>
        </div>
        <div style="font-weight:600; font-size:0.85rem; margin: 4px 0;">${inc.title}</div>
        <div style="display:flex; gap:0.5rem; align-items:center; flex-wrap:wrap; margin-top:6px;">
          <span class="badge badge-mitre">${inc.mitre_technique}</span>
          <span style="font-size:0.7rem; color:var(--text-muted);">Status: ${inc.status}</span>
          <button class="btn" style="padding:0.2rem 0.5rem;font-size:0.65rem;" onclick="exportForensicReport('${inc.id}')">Export Forensics</button>
        </div>
      </div>`;
    container.appendChild(div);
  });
}

async function loadAttackGraph() {
  renderDemoGraph();
}

function renderDemoGraph() {
  const container = document.getElementById("attack-graph");
  if (!container || typeof d3 === "undefined") return;
  container.innerHTML = "";

  const width = container.clientWidth || 500;
  const height = container.clientHeight || 350;

  const svg = d3.select(container).append("svg").attr("width", width).attr("height", height);

  const colorMap = { host: "#06b6d4", process: "#8b5cf6", remote_ip: "#ef4444", file: "#f59e0b" };
  const riskToRadius = r => 8 + (r / 100) * 16;

  const simulation = d3.forceSimulation(MOCK_GRAPH.nodes)
    .force("link", d3.forceLink(MOCK_GRAPH.links).id(d => d.id).distance(100))
    .force("charge", d3.forceManyBody().strength(-250))
    .force("center", d3.forceCenter(width / 2, height / 2));

  const link = svg.selectAll("line").data(MOCK_GRAPH.links).enter().append("line")
    .attr("stroke", "#ffffff22").attr("stroke-width", 1.5);

  const node = svg.selectAll("g").data(MOCK_GRAPH.nodes).enter().append("g").call(
    d3.drag()
      .on("start", (event, d) => { if (!event.active) simulation.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
      .on("drag", (event, d) => { d.fx = event.x; d.fy = event.y; })
      .on("end", (event, d) => { if (!event.active) simulation.alphaTarget(0); d.fx = null; d.fy = null; })
  );

  node.append("circle")
    .attr("r", d => riskToRadius(d.risk))
    .attr("fill", d => colorMap[d.type] || "#8b5cf6")
    .attr("fill-opacity", 0.85)
    .attr("stroke", d => colorMap[d.type] || "#8b5cf6")
    .attr("stroke-width", 2);

  node.append("text")
    .text(d => d.label)
    .attr("text-anchor", "middle")
    .attr("dy", d => riskToRadius(d.risk) + 14)
    .attr("fill", "#c4c4d4")
    .style("font-size", "10px")
    .style("font-family", "var(--font-mono)");

  simulation.on("tick", () => {
    link.attr("x1", d => d.source.x).attr("y1", d => d.source.y)
        .attr("x2", d => d.target.x).attr("y2", d => d.target.y);
    node.attr("transform", d => `translate(${d.x},${d.y})`);
  });
}

async function loadBaselines() {
  const container = document.getElementById("baselines-list");
  if (!container) return;
  const demoBaselines = [
    { metric: "process_launch_frequency", label: "Process Launch Frequency", sample_count: 142, mean: 2.3, std_dev: 0.4 },
    { metric: "network_bytes_out", label: "Network Outbound Bytes", sample_count: 98, mean: 15240.5, std_dev: 4800.2 },
    { metric: "clipboard_access_rate", label: "Clipboard Access Rate", sample_count: 37, mean: 0.8, std_dev: 0.2 },
    { metric: "disk_write_rate", label: "Disk Write Rate (B/s)", sample_count: 201, mean: 512000, std_dev: 128000 },
  ];
  container.innerHTML = demoBaselines.map(b => `
    <div style="display:flex; justify-content:space-between; align-items:center; padding:0.5rem 0; border-bottom:1px solid var(--border-glass); font-size:0.8rem;">
      <span style="color:var(--text-primary)">${b.label}</span>
      <div style="display:flex; gap:1rem; color:var(--text-muted); font-family:var(--font-mono); font-size:0.75rem;">
        <span>n=${b.sample_count}</span>
        <span>μ=${typeof b.mean === 'number' && b.mean > 1000 ? (b.mean/1024).toFixed(1)+'K' : b.mean.toFixed(2)}</span>
        <span>σ=${typeof b.std_dev === 'number' && b.std_dev > 1000 ? (b.std_dev/1024).toFixed(1)+'K' : b.std_dev.toFixed(2)}</span>
      </div>
    </div>`).join("");
}

async function exportForensicReport(eventId) {
  alert(`📄 Forensic Report — Demo Mode\n\nReport ID: FORENSIC-RPT-${Math.random().toString(36).substr(2,8).toUpperCase()}\nEvent: ${eventId}\nVerdict: VERIFIED_UNALTERED_TELEMETRY\n\n(In local mode, this opens a full printable NIST SP 800-86 report!)`);
}

async function terminatePID(pid) {
  alert(`🛡️ Demo Mode — Process Termination Playbook\nPID: ${pid}\n\n(In local mode, this sends a termination signal via the FastAPI backend!)`);
}

async function quarantineIP(ip) {
  alert(`🔥 Demo Mode — Firewall Quarantine Playbook\nIP: ${ip}\n\n(In local mode, this registers a Windows Defender Firewall block rule via netsh!)`);
}

async function analyzeUrl() {
  const urlInput = document.getElementById("url-input");
  const resultsDiv = document.getElementById("url-results");
  if (!urlInput || !resultsDiv) return;
  const url = urlInput.value.trim();
  if (!url) { alert("Please enter a URL first."); return; }
  const isPhishing = url.includes("login") || url.includes("verify") || url.includes("secure") || url.includes("account") || url.includes("update");
  const score = isPhishing ? (0.82 + Math.random() * 0.15).toFixed(3) : (0.05 + Math.random() * 0.15).toFixed(3);
  resultsDiv.innerHTML = `<div class="event-item ${isPhishing ? 'high' : 'info'}" style="margin-top:1rem;">
    <div><strong>URL:</strong> <span style="font-family:var(--font-mono);font-size:0.8rem;">${escapeHtml(url)}</span></div>
    <div style="margin-top:6px;"><strong>Verdict:</strong> <span style="color:${isPhishing ? 'var(--accent-red)' : 'var(--accent-green)'};font-weight:700;">${isPhishing ? '🚨 PHISHING DETECTED' : '✅ LEGITIMATE'}</span></div>
    <div><strong>Confidence:</strong> ${(parseFloat(score)*100).toFixed(1)}%</div>
    <div><strong>Model:</strong> ONNX Hybrid ML Classifier (Demo Mode)</div>
  </div>`;
}

async function runYaraScan() {
  const fileInput = document.getElementById("file-scan-input");
  const resultsDiv = document.getElementById("yara-results");
  if (!fileInput || !resultsDiv) return;
  const filepath = fileInput.value.trim();
  if (!filepath) { alert("Please enter a file path first."); return; }
  const isMalicious = filepath.toLowerCase().includes("ransomware") || filepath.toLowerCase().includes("shell") || filepath.toLowerCase().includes("payload");
  resultsDiv.innerHTML = `<div class="event-item ${isMalicious ? 'critical' : 'info'}" style="margin-top:1rem;">
    <div><strong>File:</strong> <span style="font-family:var(--font-mono);font-size:0.75rem;">${escapeHtml(filepath)}</span></div>
    <div style="margin-top:6px;"><strong>Verdict:</strong> <span style="color:${isMalicious ? 'var(--accent-red)' : 'var(--accent-green)'};font-weight:700;">${isMalicious ? '🚨 MALICIOUS_PAYLOAD (Risk: 95/100)' : '✅ CLEAN (Risk: 5/100)'}</span></div>
    ${isMalicious ? '<div><strong>YARA Match:</strong> Ransomware_ShadowCopy_Deletion</div><div><strong>MITRE:</strong> T1486 — Data Encrypted for Impact</div>' : '<div>No malicious signatures detected.</div>'}
  </div>`;
}
