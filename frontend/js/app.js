/**
 * Personal AI Cyber Digital Twin - Main Frontend Application Client (Expanded Multi-Tab & Attack Simulator)
 */

const API_BASE = "http://127.0.0.1:8000/api/v1";
const WS_URL = "ws://127.0.0.1:8000/ws";

let socket = null;

document.addEventListener("DOMContentLoaded", () => {
  setupTabNavigation();
  initDashboard();
  initWebSocket();
  setupChatListeners();
  setupPhishingScanner();
  setupMalwareScanner();
  loadAttackGraph();
  
  const refreshBtn = document.getElementById("refresh-graph-btn");
  if (refreshBtn) refreshBtn.addEventListener("click", loadAttackGraph);
});

function setupTabNavigation() {
  const tabs = document.querySelectorAll(".nav-tab");
  tabs.forEach(tab => {
    tab.addEventListener("click", () => {
      tabs.forEach(t => t.classList.remove("active"));
      tab.classList.add("active");
      
      const targetId = tab.getAttribute("data-tab");
      document.querySelectorAll(".tab-content").forEach(content => {
        content.style.display = content.id === targetId ? "block" : "none";
      });
      
      if (targetId === "tab-overview") {
        setTimeout(loadAttackGraph, 100);
      } else if (targetId === "tab-twin") {
        loadBaselines();
      }
    });
  });
}

async function initDashboard() {
  try {
    const res = await fetch(`${API_BASE}/dashboard/summary`);
    const data = await res.json();
    
    updateTwinMeter(data.twin_health);
    loadRecentEvents();
    loadIncidents();
    loadBaselines();
  } catch (err) {
    console.error("Error loading dashboard metrics:", err);
  }
}

async function loadBaselines() {
  try {
    const res = await fetch(`${API_BASE}/dashboard/baselines`);
    const data = await res.json();
    
    const container = document.getElementById("baselines-list");
    if (!container) return;
    container.innerHTML = "";
    
    if (data.length === 0) {
      container.innerHTML = `<div style="color: var(--text-muted);">No baselines recorded yet. Start opening applications or copying text to seed profiles.</div>`;
      return;
    }
    
    data.forEach(b => {
      const item = document.createElement("div");
      item.style.padding = "6px 0";
      item.style.borderBottom = "1px solid rgba(255,255,255,0.05)";
      item.innerHTML = `
        <div style="display: flex; justify-content: space-between; font-size: 0.85rem;">
          <strong style="color: var(--accent-cyan); font-family: var(--font-mono);">${b.feature_name}</strong>
          <span style="color: var(--accent-green); font-size: 0.75rem;">Samples: ${b.sample_count}</span>
        </div>
        <div style="color: var(--text-muted); font-size: 0.75rem; display: flex; flex-wrap: wrap; gap: 0.8rem; margin-top: 4px; font-family: var(--font-mono);">
          <span>Entity: ${b.entity_id}</span>
          <span>Mean: ${b.mean_val}</span>
          <span>StdDev: ${b.std_dev}</span>
          <span>Updated: ${new Date(b.last_updated + 'Z').toLocaleTimeString()}</span>
        </div>
      `;
      container.appendChild(item);
    });
  } catch (err) {
    console.error("Error loading baseline data:", err);
  }
}

function initWebSocket() {
  socket = new WebSocket(WS_URL);
  
  socket.onopen = () => {
    console.log("WebSocket connected to Digital Twin Core server.");
    document.getElementById("connection-status").textContent = "LOCAL AGENT ACTIVE";
  };
  
  socket.onmessage = (event) => {
    const payload = JSON.parse(event.data);
    
    if (payload.type === "telemetry_event") {
      prependTelemetryEvent(payload.data);
      loadIncidents();
      loadAttackGraph();
      
      // Animate canary compromise widget
      if (payload.data.source_component === "FIMMonitor") {
        animateCanaryAlert(payload.data.raw_payload);
      }
    } else if (payload.type === "health_pulse") {
      updateTwinMeter(payload.data);
    }
  };
  
  socket.onclose = () => {
    console.warn("WebSocket connection lost. Retrying in 3s...");
    document.getElementById("connection-status").textContent = "DISCONNECTED - RETRYING";
    setTimeout(initWebSocket, 3000);
  };
}

function animateCanaryAlert(raw) {
  const filename = raw.filename;
  const globalStatus = document.getElementById("canary-global-status");
  let statusElem = null;
  
  if (filename === "passwords_vault.txt") {
    statusElem = document.getElementById("canary-status-passwords");
  } else if (filename === "financial_ledger.csv") {
    statusElem = document.getElementById("canary-status-ledger");
  }
  
  if (globalStatus) {
    globalStatus.innerHTML = "● INTRUSION BLOCKED";
    globalStatus.style.color = "var(--accent-red)";
  }
  
  if (statusElem) {
    statusElem.innerHTML = "COMPROMISED (PID KILLED)";
    statusElem.style.color = "var(--accent-red)";
  }
  
  setTimeout(() => {
    if (globalStatus) {
      globalStatus.innerHTML = "● ACTIVE";
      globalStatus.style.color = "var(--accent-green)";
    }
    if (statusElem) {
      statusElem.innerHTML = "SECURE (RESTORED)";
      statusElem.style.color = "var(--accent-green)";
    }
  }, 4000);
}

function updateTwinMeter(healthData) {
  if (!healthData) return;
  const score = healthData.health_score;
  
  const scoreElem = document.getElementById("twin-score-text");
  const statusElem = document.getElementById("twin-status-text");
  const circleElem = document.getElementById("gauge-circle");
  
  if (scoreElem) scoreElem.textContent = `${score}%`;
  if (statusElem) statusElem.textContent = healthData.status;
  
  if (circleElem) {
    const offset = 440 - (440 * score / 100);
    circleElem.style.strokeDashoffset = offset;
  }
}

async function loadRecentEvents() {
  try {
    const res = await fetch(`${API_BASE}/telemetry/events?limit=30`);
    const events = await res.json();
    
    const container = document.getElementById("event-stream-list");
    if (!container) return;
    container.innerHTML = "";
    
    events.forEach(ev => prependTelemetryEvent(ev));
  } catch (err) {
    console.error("Error fetching telemetry events:", err);
  }
}

function prependTelemetryEvent(ev) {
  const container = document.getElementById("event-stream-list");
  if (!container) return;
  
  const timeStr = new Date(ev.created_at || Date.now()).toLocaleTimeString();
  const payloadStr = JSON.stringify(ev.raw_payload || {});
  const pid = ev.raw_payload ? ev.raw_payload.pid : null;
  const remoteIp = ev.raw_payload && ev.raw_payload.remote_ip ? ev.raw_payload.remote_ip : null;
  
  const div = document.createElement("div");
  div.className = `event-item ${ev.severity || 'info'}`;
  div.innerHTML = `
    <div style="width: 100%;">
      <div class="event-meta">
        <span class="event-type">${ev.event_type}</span>
        <span class="event-time">${timeStr}</span>
      </div>
      <div class="event-payload">${escapeHtml(payloadStr.substring(0, 85))}${payloadStr.length > 85 ? '...' : ''}</div>
      <div style="margin-top: 6px; display: flex; gap: 0.5rem; align-items: center; flex-wrap: wrap;">
        ${ev.mitre_technique ? `<span class="badge badge-mitre">${ev.mitre_technique}</span>` : ''}
        ${pid ? `<button class="btn" style="padding: 0.2rem 0.5rem; font-size: 0.65rem; background: var(--accent-red); color: #fff;" onclick="terminatePID(${pid})">Terminate PID ${pid}</button>` : ''}
        ${remoteIp ? `<button class="btn" style="padding: 0.2rem 0.5rem; font-size: 0.65rem; background: var(--accent-purple); color: #fff;" onclick="quarantineIP('${remoteIp}')">Quarantine IP ${remoteIp}</button>` : ''}
      </div>
    </div>
  `;
  
  container.prepend(div);
  
  while (container.children.length > 50) {
    container.removeChild(container.lastChild);
  }
}

async function loadIncidents() {
  try {
    const res = await fetch(`${API_BASE}/incidents/incidents`);
    const incidents = await res.json();
    
    const containers = [
      document.getElementById("incidents-container"),
      document.getElementById("incidents-container-tab")
    ];
    
    containers.forEach(container => {
      if (!container) return;
      container.innerHTML = "";
      
      if (incidents.length === 0) {
        container.innerHTML = `<div style="color: var(--text-muted); font-size: 0.85rem;">No active high-risk incidents detected. Endpoint baseline is clean.</div>`;
        return;
      }
      
      incidents.forEach(inc => {
        const card = document.createElement("div");
        card.className = "card";
        card.style.marginBottom = "0.75rem";
        card.style.borderLeft = "4px solid var(--accent-red)";
        card.innerHTML = `
          <div style="display: flex; justify-content: space-between; margin-bottom: 0.5rem;">
            <strong style="color: var(--accent-red); font-size: 0.9rem;">${inc.mitre_technique}</strong>
            <span style="font-family: var(--font-mono); font-size: 0.8rem; color: var(--accent-orange);">Risk: ${inc.risk_score}/100</span>
          </div>
          <p style="font-size: 0.8rem; color: var(--text-muted); margin-bottom: 0.5rem;">${inc.soc_analysis.xai_explainer.human_readable_rationale}</p>
          <div style="display: flex; gap: 0.5rem;">
            <button class="btn" style="padding: 0.4rem 0.8rem; font-size: 0.75rem;" onclick="viewXAIExplanation('${inc.event_id}')">Inspect XAI Root Cause</button>
            <button class="btn" style="padding: 0.4rem 0.8rem; font-size: 0.75rem; background: var(--accent-purple); color: #fff;" onclick="exportForensicReport('${inc.event_id}')">Export Forensics</button>
          </div>
        `;
        container.appendChild(card);
      });
    });
  } catch (err) {
    console.error("Error loading incidents:", err);
  }
}

async function triggerSimulatedAttack(scenario) {
  const outputDiv = document.getElementById("simulation-output");
  if (outputDiv) {
    outputDiv.style.display = "block";
    outputDiv.innerHTML = `[SIMULATION SUITE] Launching MITRE scenario: ${scenario.toUpperCase()}...`;
  }
  
  try {
    const res = await fetch(`${API_BASE}/simulation/trigger`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scenario: scenario })
    });
    const data = await res.json();
    
    if (outputDiv) {
      outputDiv.innerHTML = `
        <div><strong style="color: var(--accent-green);">ATTACK SIMULATED SUCCESSFULLY!</strong></div>
        <div>Scenario: ${data.scenario} | Mitre: ${data.event.mitre_technique}</div>
        <div style="margin-top: 0.5rem; color: var(--accent-red);">SOC Analyst Assessment: ${data.soc_analysis.soc_agent}</div>
        <div style="color: var(--text-muted); margin-top: 4px;">XAI Rationale: ${data.soc_analysis.xai_explainer.human_readable_rationale}</div>
        <div style="margin-top: 0.5rem; color: var(--accent-orange);">Updated Digital Twin Security Index: ${data.updated_twin_health.health_score}% (${data.updated_twin_health.status})</div>
      `;
    }
    
    updateTwinMeter(data.updated_twin_health);
    loadRecentEvents();
    loadIncidents();
    loadAttackGraph();
    
  } catch (err) {
    if (outputDiv) outputDiv.innerHTML = `<span style="color: var(--accent-red);">Failed to trigger simulated attack scenario.</span>`;
  }
}

async function viewXAIExplanation(eventId) {
  try {
    const res = await fetch(`${API_BASE}/incidents/evaluate-event/${eventId}`, { method: 'POST' });
    const data = await res.json();
    alert(`[XAI EXPLAINABLE AI REPORT]\n\n${data.xai_explainer.human_readable_rationale}\n\nExecution Trace:\n${data.forensic_agent.join('\n')}`);
  } catch (err) {
    alert("Could not load XAI breakdown for event.");
  }
}

function exportForensicReport(eventId) {
  window.open(`report.html?event_id=${eventId}`, '_blank');
}

async function quarantineIP(ip) {
  if (!confirm(`Are you sure you want to register a Windows Firewall block rule for remote IP ${ip}?`)) return;
  
  try {
    const res = await fetch(`${API_BASE}/remediation/quarantine-ip`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ip: ip })
    });
    const data = await res.json();
    alert(data.message);
  } catch (err) {
    alert(`Failed to trigger quarantine playbook for IP ${ip}.`);
  }
}

async function terminatePID(pid) {
  if (!confirm(`Are you sure you want to trigger the Process Termination Playbook for PID ${pid}?`)) return;
  
  try {
    const res = await fetch(`${API_BASE}/remediation/terminate-process`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ pid: pid, reason: "User triggered process isolation via dashboard" })
    });
    const data = await res.json();
    alert(data.message);
  } catch (err) {
    alert(`Failed to trigger termination playbook for PID ${pid}.`);
  }
}

/* Render D3.js Force-Directed Attack Graph */
async function loadAttackGraph() {
  const svg = d3.select("#d3-graph-svg");
  if (svg.empty()) return;
  
  svg.selectAll("*").remove();
  
  try {
    const res = await fetch(`${API_BASE}/graph/attack-graph`);
    const graphData = await res.json();
    
    if (!graphData.nodes || graphData.nodes.length === 0) return;
    
    const width = document.getElementById("attack-graph-container").clientWidth || 400;
    const height = 260;
    
    const simulation = d3.forceSimulation(graphData.nodes)
      .force("link", d3.forceLink(graphData.links).id(d => d.id).distance(60))
      .force("charge", d3.forceManyBody().strength(-120))
      .force("center", d3.forceCenter(width / 2, height / 2));
      
    const link = svg.append("g")
      .selectAll("line")
      .data(graphData.links)
      .enter().append("line")
      .attr("stroke", "rgba(0, 243, 255, 0.25)")
      .attr("stroke-width", 1.5);
      
    const node = svg.append("g")
      .selectAll("circle")
      .data(graphData.nodes)
      .enter().append("circle")
      .attr("r", d => d.type === "host" ? 10 : (d.risk > 50 ? 8 : 5))
      .attr("fill", d => {
        if (d.type === "host") return "#00f3ff";
        if (d.type === "network") return "#9d4edd";
        return d.risk > 50 ? "#ff0055" : "#00ff88";
      })
      .attr("stroke", "#000")
      .attr("stroke-width", 1.5)
      .call(d3.drag()
        .on("start", dragstarted)
        .on("drag", dragged)
        .on("end", dragended));
        
    node.append("title")
      .text(d => `${d.label} (Risk: ${d.risk})`);
      
    simulation.on("tick", () => {
      link
        .attr("x1", d => d.source.x)
        .attr("y1", d => d.source.y)
        .attr("x2", d => d.target.x)
        .attr("y2", d => d.target.y);
        
      node
        .attr("cx", d => d.x = Math.max(10, Math.min(width - 10, d.x)))
        .attr("cy", d => d.y = Math.max(10, Math.min(height - 10, d.y)));
    });
    
    function dragstarted(event) {
      if (!event.active) simulation.alphaTarget(0.3).restart();
      event.subject.fx = event.subject.x;
      event.subject.fy = event.subject.y;
    }
    
    function dragged(event) {
      event.subject.fx = event.x;
      event.subject.fy = event.y;
    }
    
    function dragended(event) {
      if (!event.active) simulation.alphaTarget(0);
      event.subject.fx = null;
      event.subject.fy = null;
    }
    
  } catch (err) {
    console.error("Error building D3 attack graph:", err);
  }
}

function setupChatListeners() {
  const btn = document.getElementById("chat-send-btn");
  const input = document.getElementById("chat-input");
  
  if (btn && input) {
    btn.addEventListener("click", () => sendChatMessage());
    input.addEventListener("keypress", (e) => {
      if (e.key === "Enter") sendChatMessage();
    });
  }
}

async function sendChatMessage() {
  const input = document.getElementById("chat-input");
  const container = document.getElementById("chat-messages-box");
  const query = input.value.trim();
  
  if (!query || !container) return;
  
  const userDiv = document.createElement("div");
  userDiv.className = "chat-bubble user";
  userDiv.textContent = query;
  container.appendChild(userDiv);
  
  input.value = "";
  container.scrollTop = container.scrollHeight;
  
  try {
    const res = await fetch(`${API_BASE}/agent/query`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ query: query })
    });
    const data = await res.json();
    
    const botDiv = document.createElement("div");
    botDiv.className = "chat-bubble bot";
    botDiv.textContent = data.response;
    container.appendChild(botDiv);
    container.scrollTop = container.scrollHeight;
  } catch (err) {
    console.error("Error querying AI agent:", err);
  }
}

function setupPhishingScanner() {
  const btn = document.getElementById("scan-url-btn");
  const input = document.getElementById("url-input");
  const resultDiv = document.getElementById("phishing-result");
  
  if (btn && input && resultDiv) {
    btn.addEventListener("click", async () => {
      const url = input.value.trim();
      if (!url) return;
      
      resultDiv.innerHTML = `<span style="color: var(--accent-cyan);">Evaluating hybrid ONNX ML model & heuristics...</span>`;
      
      try {
        const res = await fetch(`${API_BASE}/telemetry/analyze-url`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url: url })
        });
        const data = await res.json();
        
        let color = "var(--accent-green)";
        if (data.verdict === "SUSPICIOUS") color = "var(--accent-orange)";
        if (data.verdict === "CRITICAL_PHISHING") color = "var(--accent-red)";
        
        resultDiv.innerHTML = `
          <div style="margin-top: 0.5rem; border-top: 1px solid var(--border-glass); padding-top: 0.5rem;">
            <div style="font-weight: 700; color: ${color};">Verdict: ${data.verdict} (Hybrid Risk: ${data.risk_score}/100)</div>
            <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 4px;">ONNX ML Probability: ${(data.ml_model_prediction.ml_probability * 100).toFixed(1)}% (Latency: ${data.ml_model_prediction.inference_time_ms}ms)</div>
            ${data.reasons.length > 0 ? `<ul style="font-size: 0.75rem; color: var(--accent-orange); margin-left: 1rem; margin-top: 4px;">${data.reasons.map(r => `<li>${r}</li>`).join('')}</ul>` : ''}
          </div>
        `;
      } catch (err) {
        resultDiv.innerHTML = `<span style="color: var(--accent-red);">Error analyzing target URL.</span>`;
      }
    });
  }
}

function setupMalwareScanner() {
  const btn = document.getElementById("scan-file-btn");
  const input = document.getElementById("filepath-input");
  const resultDiv = document.getElementById("malware-result");
  
  if (btn && input && resultDiv) {
    btn.addEventListener("click", async () => {
      const path = input.value.trim();
      if (!path) return;
      
      resultDiv.innerHTML = `<span style="color: var(--accent-cyan);">Running YARA rules, byte entropy & suspicious import scan...</span>`;
      
      try {
        const res = await fetch(`${API_BASE}/malware/scan-file`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ filepath: path })
        });
        const data = await res.json();
        
        let color = "var(--accent-green)";
        if (data.verdict === "SUSPICIOUS_PACKED_BINARY") color = "var(--accent-orange)";
        if (data.verdict === "MALICIOUS_PAYLOAD") color = "var(--accent-red)";
        
        resultDiv.innerHTML = `
          <div style="margin-top: 0.5rem; border-top: 1px solid var(--border-glass); padding-top: 0.5rem;">
            <div style="font-weight: 700; color: ${color};">Verdict: ${data.verdict} (Risk Score: ${data.risk_score}/100)</div>
            <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 4px;">Byte Entropy: ${data.entropy} / 8.0 (Packed: ${data.is_packed})</div>
            <div style="font-size: 0.75rem; font-family: var(--font-mono); color: var(--text-dim); margin-top: 2px;">SHA256: ${data.sha256 ? data.sha256.substring(0, 24) + '...' : 'N/A'}</div>
            ${data.findings.length > 0 ? `<ul style="font-size: 0.75rem; color: var(--accent-orange); margin-left: 1rem; margin-top: 4px;">${data.findings.map(f => `<li>${f}</li>`).join('')}</ul>` : ''}
          </div>
        `;
      } catch (err) {
        resultDiv.innerHTML = `<span style="color: var(--accent-red);">Error analyzing binary file. Ensure path exists.</span>`;
      }
    });
  }
}

function escapeHtml(str) {
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
