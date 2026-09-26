// IMG4N6 v2 frontend
const API_BASE = window.location.origin;
let currentSessionId = null;
let mapInstance = null;

// ---------------------------------------------------------------------------
// Matrix rain (kept from v1, lightly cleaned)
// ---------------------------------------------------------------------------
function createMatrixRain() {
  const bg = document.getElementById("matrixBg");
  const chars = "01アイウエオカキクケコサシスセソABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";
  let columns = Math.floor(window.innerWidth / 20);
  function drop(i) {
    if (Math.random() > 0.985) {
      const c = document.createElement("div");
      c.className = "matrix-char";
      c.textContent = chars[(Math.random() * chars.length) | 0];
      c.style.cssText =
        `left:${i * 20}px;top:-20px;position:absolute;` +
        `color:${Math.random() > 0.95 ? "#fff" : "#00ff88"};` +
        `font:${(Math.random() * 6 + 12) | 0}px 'Courier New',monospace;` +
        `text-shadow:0 0 5px currentColor;z-index:-1;opacity:.8;` +
        `animation:matrix-fall ${(Math.random() * 3 + 2).toFixed(1)}s linear forwards`;
      bg.appendChild(c);
      setTimeout(() => c.remove(), 5000);
    }
  }
  function animate() {
    for (let i = 0; i < columns; i++) drop(i);
    requestAnimationFrame(animate);
  }
  animate();
  window.addEventListener("resize", () => {
    columns = Math.floor(window.innerWidth / 20);
  });
}

// ---------------------------------------------------------------------------
// DOM refs
// ---------------------------------------------------------------------------
const scanButton = document.getElementById("scanButton");
const cancelButton = document.getElementById("cancelButton");
const resultsArea = document.getElementById("resultsArea");
const loading = document.getElementById("loading");
const loadingText = document.getElementById("loadingText");
const progressBar = document.getElementById("progressBar");
const progressFill = document.getElementById("progressFill");
const vtApiKey = document.getElementById("vtApiKey");

document.querySelectorAll(".option-card").forEach((card) =>
  card.addEventListener("click", function () {
    document.querySelectorAll(".option-card").forEach((c) => c.classList.remove("selected"));
    this.classList.add("selected");
  })
);

// ---------------------------------------------------------------------------
// Path validation
// ---------------------------------------------------------------------------
async function validateFolderPath() {
  const folderPath = document.getElementById("folderPath").value.trim();
  const box = document.getElementById("pathValidation");
  if (!folderPath) {
    box.innerHTML = '<div style="color:#ff4444">❌ Please enter a folder path</div>';
    return;
  }
  box.innerHTML = '<div style="color:#ffaa00">🔍 Validating…</div>';
  try {
    const res = await fetch(`${API_BASE}/api/validate-path`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ folder_path: folderPath }),
    });
    const r = await res.json();
    if (r.is_safe) {
      box.innerHTML = `<div style="color:#00ff88">✅ ${escapeHtml(r.message)}</div>`;
      scanButton.disabled = false;
    } else {
      box.innerHTML = `<div style="color:#ff4444">❌ ${escapeHtml(r.message)}</div>`;
      scanButton.disabled = true;
    }
  } catch (e) {
    box.innerHTML = `<div style="color:#ff4444">❌ ${escapeHtml(e.message)}</div>`;
    scanButton.disabled = true;
  }
}

function clearValidation() {
  document.getElementById("pathValidation").innerHTML = "";
  scanButton.disabled = true;
}

// ---------------------------------------------------------------------------
// Scanning
// ---------------------------------------------------------------------------
async function startScan() {
  const folderPath = document.getElementById("folderPath").value.trim();
  const level = document.querySelector(".option-card.selected").dataset.level;
  if (!folderPath) return alert("Enter and validate a folder path first");

  loading.style.display = "block";
  progressBar.style.display = "block";
  scanButton.disabled = true;
  cancelButton.style.display = "block";
  resultsArea.innerHTML = "";
  document.getElementById("exportBar").style.display = "none";
  document.getElementById("mapContainer").style.display = "none";
  document.getElementById("duplicatesBox").innerHTML = "";

  try {
    const res = await fetch(`${API_BASE}/api/scan-folder`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        folder_path: folderPath,
        analysis_level: level,
        vt_api_key: vtApiKey.value.trim(),
      }),
    });
    if (!res.ok) throw new Error((await res.json()).error || "Scan failed");
    currentSessionId = (await res.json()).session_id;
    pollProgress();
  } catch (e) {
    endScanUI();
    resultsArea.innerHTML = errorBox(`Scan failed: ${e.message}`);
  }
}

async function cancelScan() {
  if (!currentSessionId) return;
  cancelButton.disabled = true;
  cancelButton.textContent = "Cancelling…";
  await fetch(`${API_BASE}/api/cancel/${currentSessionId}`, { method: "POST" });
}

async function pollProgress() {
  if (!currentSessionId) return;
  try {
    const res = await fetch(`${API_BASE}/api/status/${currentSessionId}`);
    const s = await res.json();
    if (!res.ok) throw new Error(s.error || "Status check failed");

    progressFill.style.width = (s.progress || 0) + "%";
    if (s.status === "finding_files") loadingText.textContent = "Finding image files…";
    else if (s.current_file) loadingText.textContent = `Analyzing: ${s.current_file}`;
    else loadingText.textContent = "Processing…";

    if (s.results && s.results.length) renderResults(s.results, s.duplicates || []);

    if (s.status === "completed" || s.status === "cancelled") {
      completeScan(s);
    } else if (s.status === "error") {
      throw new Error(s.error || "Scan failed on server");
    } else {
      setTimeout(pollProgress, 900);
    }
  } catch (e) {
    endScanUI();
    resultsArea.innerHTML = errorBox(`Error: ${e.message}`);
  }
}

function completeScan(s) {
  endScanUI();
  renderResults(s.results, s.duplicates || []);
  updateStats(s.results, s.duplicates || []);
  renderMap(s.results);
  if (s.results.length) document.getElementById("exportBar").style.display = "flex";
  if (s.status === "cancelled") {
    resultsArea.insertAdjacentHTML(
      "afterbegin",
      '<div style="color:#ffaa00;text-align:center;margin-bottom:10px">⏹ Scan cancelled — partial results shown</div>'
    );
  }
  loadHistory();
  const sid = currentSessionId;
  document.querySelectorAll(".export-btn").forEach((b) => {
    b.onclick = () => window.open(`${API_BASE}/api/export/${sid}?fmt=${b.dataset.fmt}`, "_blank");
  });
  currentSessionId = null;
}

function endScanUI() {
  loading.style.display = "none";
  progressBar.style.display = "none";
  scanButton.disabled = false;
  cancelButton.style.display = "none";
  cancelButton.disabled = false;
  cancelButton.textContent = "⏹ Cancel";
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------
function renderResults(results, duplicates) {
  const summary = document.getElementById("detectionSummary");
  summary.style.display = "flex";
  const aiN = results.filter((r) => (r.ai_provenance || {}).detected || r.ai_probability >= 0.3).length;
  const thN = results.filter((r) => r.status === "threats").length;
  const clN = results.filter((r) => r.status === "clean").length;
  document.getElementById("aiSummary").textContent = aiN;
  document.getElementById("threatSummary").textContent = thN;
  document.getElementById("modernSummary").textContent = duplicates.length;
  document.getElementById("cleanSummary").textContent = clN;

  renderDuplicates(duplicates);

  resultsArea.innerHTML = results.map(renderCard).join("");
}

function renderCard(r) {
  if (r.status === "error") {
    return `<div class="result-item error-item"><strong>❌ ${escapeHtml(r.filename)}</strong>
      <div style="color:#ff8888;font-size:0.85rem">${escapeHtml(r.error || "Error")}</div></div>`;
  }

  const prov = r.ai_provenance || {};
  let cls = "clean-item", icon = "✅";
  if (prov.detected) { cls = "ai-item"; icon = "🤖"; }
  else if (r.status === "threats") { cls = "threat-item"; icon = "⚠️"; }
  else if (r.status === "warnings") { cls = "warning-item"; icon = "🔶"; }

  let body = "";

  // AI provenance — the headline feature
  if (prov.detected) {
    body += `<div class="ai-details" style="margin-top:8px">
      <div style="color:#b98bff;font-weight:bold">🤖 AI-GENERATED (${escapeHtml(r.ai_confidence)})</div>
      <div style="font-size:0.85rem;color:#ccc">Generator: <b>${escapeHtml(String(prov.generator))}</b></div>
      <div style="font-size:0.8rem;color:#999">Evidence: ${escapeHtml(String(prov.source))}</div>`;
    if (prov.prompt) {
      body += `<div style="font-size:0.8rem;color:#8fe;margin-top:5px;background:rgba(0,0,0,.3);padding:6px;border-radius:4px">
        <b>Prompt:</b> ${escapeHtml(prov.prompt.slice(0, 400))}${prov.prompt.length > 400 ? "…" : ""}</div>`;
    }
    body += `</div>`;
  } else if (r.ai_probability >= 0.15) {
    body += `<div style="font-size:0.82rem;color:#aa88cc;margin-top:6px">
      🤖 Possible AI (${escapeHtml(r.ai_confidence)}, ${Math.round(r.ai_probability * 100)}%) — heuristic only, not conclusive</div>`;
  }

  (r.threats || []).forEach((t) => {
    body += `<div style="font-size:0.83rem;color:#ff6b6b;margin-top:4px">⚠️ <b>${escapeHtml(t.type)}:</b> ${escapeHtml(t.description)}</div>`;
  });
  (r.warnings || []).forEach((w) => {
    body += `<div style="font-size:0.82rem;color:#ffb84d;margin-top:3px">🔶 ${escapeHtml(w.description)}</div>`;
  });

  if (r.ela && r.ela.suspicious) {
    body += `<div style="font-size:0.82rem;color:#ffb84d;margin-top:3px">🔬 ELA: ${escapeHtml(r.ela.note)}</div>`;
  }
  if (r.gps) {
    body += `<div style="font-size:0.8rem;color:#7fd;margin-top:3px">📍 GPS: ${r.gps.lat}, ${r.gps.lon}</div>`;
  }
  if (r.camera && (r.camera.Make || r.camera.Model)) {
    body += `<div style="font-size:0.78rem;color:#888;margin-top:3px">📷 ${escapeHtml((r.camera.Make || "") + " " + (r.camera.Model || ""))}</div>`;
  }
  if (r.cached) body += `<div style="font-size:0.72rem;color:#666;margin-top:3px">⚡ from cache</div>`;

  return `<div class="result-item ${cls}">
    <strong>${icon} ${escapeHtml(r.filename)}</strong>
    <span style="float:right;color:#888;font-size:0.75rem">${formatBytes(r.file_size)}</span>
    <div style="font-family:monospace;font-size:0.7rem;color:#666;margin-top:2px">${(r.sha256 || "").slice(0, 32)}…</div>
    ${body}
  </div>`;
}

function renderDuplicates(duplicates) {
  const box = document.getElementById("duplicatesBox");
  if (!duplicates || !duplicates.length) { box.innerHTML = ""; return; }
  box.innerHTML =
    `<div style="background:rgba(255,170,0,.08);border:1px solid rgba(255,170,0,.3);border-radius:8px;padding:10px;margin-bottom:12px">
      <div style="color:#ffaa00;font-weight:bold;margin-bottom:6px">📋 ${duplicates.length} Duplicate Group(s)</div>` +
    duplicates
      .map(
        (g) =>
          `<div style="font-size:0.82rem;color:#ccc;margin-top:4px">
            <b>${g.type === "exact" ? "Exact" : "Near"}:</b> ${g.files.map((f) => escapeHtml(basename(f))).join(", ")}</div>`
      )
      .join("") +
    `</div>`;
}

function renderMap(results) {
  const geo = results.filter((r) => r.gps);
  const container = document.getElementById("mapContainer");
  if (!geo.length || typeof L === "undefined") return;
  container.style.display = "block";
  if (mapInstance) { mapInstance.remove(); mapInstance = null; }
  mapInstance = L.map(container).setView([geo[0].gps.lat, geo[0].gps.lon], 5);
  L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
    attribution: "&copy; OpenStreetMap",
    maxZoom: 18,
  }).addTo(mapInstance);
  const markers = geo.map((r) =>
    L.marker([r.gps.lat, r.gps.lon]).bindPopup(escapeHtml(r.filename)).addTo(mapInstance)
  );
  if (markers.length > 1) {
    mapInstance.fitBounds(L.featureGroup(markers).getBounds().pad(0.2));
  }
}

function updateStats(results, duplicates) {
  setNum("totalScans", results.length);
  setNum("aiDetected", results.filter((r) => (r.ai_provenance || {}).detected).length);
  setNum("threatsFound", results.filter((r) => r.status === "threats").length);
  setNum("modernThreats", duplicates.length);
  setNum("cleanFiles", results.filter((r) => r.status === "clean").length);
  const flagged = results.filter((r) => r.status !== "clean").length;
  document.getElementById("detectionRate").textContent =
    results.length ? Math.round((flagged / results.length) * 100) + "%" : "0%";
}

// ---------------------------------------------------------------------------
// History
// ---------------------------------------------------------------------------
async function loadHistory() {
  try {
    const res = await fetch(`${API_BASE}/api/history`);
    const rows = await res.json();
    const box = document.getElementById("historyBox");
    if (!Array.isArray(rows) || !rows.length) { box.innerHTML = ""; return; }
    box.innerHTML =
      `<div style="color:#888;font-size:0.85rem;margin-bottom:6px">🕘 Recent Scans</div>` +
      rows
        .slice(0, 5)
        .map(
          (h) =>
            `<div style="font-size:0.78rem;color:#aaa;padding:4px 0;border-bottom:1px solid rgba(255,255,255,.05)">
              ${escapeHtml(basename(h.folder))} — ${h.total} files, ${h.threats} threats, ${h.ai_flagged} AI
              <span style="float:right;color:#666">${escapeHtml((h.started || "").slice(0, 16))}</span></div>`
        )
        .join("");
  } catch (e) {
    /* non-fatal */
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])
  );
}
function basename(p) { return String(p).split(/[\\/]/).pop(); }
function formatBytes(b) {
  if (!b) return "0 B";
  const u = ["B", "KB", "MB", "GB"];
  let i = 0;
  while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
  return b.toFixed(1) + " " + u[i];
}
function setNum(id, v) { const el = document.getElementById(id); if (el) el.textContent = v; }
function errorBox(msg) {
  return `<div style="text-align:center;color:#ff4444;margin-top:40px">
    <div style="font-size:2rem">❌</div><div>${escapeHtml(msg)}</div></div>`;
}

// ---------------------------------------------------------------------------
// Wire up
// ---------------------------------------------------------------------------
document.addEventListener("DOMContentLoaded", () => {
  createMatrixRain();
  document.getElementById("validatePathBtn").addEventListener("click", validateFolderPath);
  const fp = document.getElementById("folderPath");
  fp.addEventListener("input", clearValidation);
  fp.addEventListener("keypress", (e) => { if (e.key === "Enter") validateFolderPath(); });
  scanButton.addEventListener("click", startScan);
  cancelButton.addEventListener("click", cancelScan);
  loadHistory();
});
