// ============================================================
// ThreatBarrier – Dashboard Script (Correct + Matches Service Worker)
// - Auth gate: closes/locks dashboard when logged out
// - Auto-refresh
// - Safe runtime messaging
// - Trackers count matches tracker list
// - Cookie Block/Allow works (uses BLOCK_COOKIES_FOR_DOMAIN / ALLOW_COOKIES_FOR_DOMAIN)
// ============================================================

let currentLogs = [];
let currentRules = [];
let cookieResults = [];

let refreshTimer = null;
let authTimer = null;

/* ------------------------------
   Helpers
------------------------------ */
const $ = (id) => document.getElementById(id);

function fmt(n) {
  return typeof n === "number" ? Math.round(n) : 0;
}

function safeText(idOrEl, text) {
  const el = typeof idOrEl === "string" ? $(idOrEl) : idOrEl;
  if (el) el.textContent = text;
}

function csvEscape(val) {
  if (val === null || val === undefined) return "";
  const s = String(val);
  return `"${s.replace(/"/g, '""')}"`;
}

/* ------------------------------
   Safe messaging (prevents lastError spam)
------------------------------ */
function sendMessageSafe(msg) {
  return new Promise((resolve) => {
    try {
      chrome.runtime.sendMessage(msg, (res) => {
        if (chrome.runtime.lastError) {
          resolve({ success: false, error: chrome.runtime.lastError.message });
          return;
        }
        resolve(res || { success: false, error: "No response" });
      });
    } catch (e) {
      resolve({ success: false, error: String(e?.message || e) });
    }
  });
}

/* ------------------------------
   Auth overlay + close tab on logout
------------------------------ */
async function closeThisTab() {
  try {
    chrome.tabs.getCurrent((tab) => {
      if (tab?.id) chrome.tabs.remove(tab.id);
    });
  } catch {
    // ignore
  }
}

function showLoggedOutOverlay() {
  const overlay = $("loggedOutOverlay");
  if (overlay) overlay.style.display = "flex";
}

function hideLoggedOutOverlay() {
  const overlay = $("loggedOutOverlay");
  if (overlay) overlay.style.display = "none";
}

async function enforceAuth({ closeTab = true } = {}) {
  const res = await sendMessageSafe({ type: "AUTH_STATUS" });
  const loggedIn = !!res?.loggedIn;

  if (!loggedIn) {
    showLoggedOutOverlay();
    if (closeTab) await closeThisTab();
    return false;
  }

  hideLoggedOutOverlay();
  return true;
}

/* ------------------------------
   Source label helpers
------------------------------ */
function getSourceText(log) {
  return (log && (log.phishingProvider || log.ruleId))
    ? (log.phishingProvider || log.ruleId)
    : "DNR";
}

function getSourceLabel(log) {
  const src = getSourceText(log);
  const low = String(src).toLowerCase();

  let cls = "pill-score-low";
  if (low.includes("virustotal")) cls = "pill-score-med";
  if (low.includes("openphish") || low.includes("urlhaus")) cls = "pill-score-high";

  return `<span class="tb-pill ${cls}">${src}</span>`;
}

/* ------------------------------
   Render: Trackers (returns count)
------------------------------ */
function renderTrackers(logs) {
  const list = $("trackerList");
  if (!list) return 0;

  const trackers = new Set();

  (logs || []).forEach((log) => {
    const host = String(log.trackingDomain || "").toLowerCase();
    if (!host) return;

    if (
      host.includes("google-analytics") ||
      host.includes("googletagmanager") ||
      host.includes("doubleclick") ||
      host.includes("googleads") ||
      host.includes("facebook") ||
      host.includes("fbcdn") ||
      host.includes("pixel") ||
      host.includes("analytics") ||
      host.includes("ads") ||
      host.includes("track")
    ) {
      trackers.add(host);
    }
  });

  list.innerHTML = "";
  if (trackers.size === 0) {
    list.innerHTML = "<li>No trackers detected yet.</li>";
    return 0;
  }

  [...trackers].sort().forEach((t) => {
    const li = document.createElement("li");
    li.textContent = t;
    list.appendChild(li);
  });

  return trackers.size;
}

/* ------------------------------
   Render: Logs table
------------------------------ */
function renderLogs(logs) {
  currentLogs = Array.isArray(logs) ? logs : [];
  const tbody = document.querySelector("#logsTable tbody");
  if (!tbody) return;

  tbody.innerHTML = "";

  if (!currentLogs.length) {
    tbody.innerHTML = "<tr><td colspan='7' class='tb-empty'>No logs yet.</td></tr>";
    return;
  }

  [...currentLogs].slice().reverse().forEach((log, i) => {
    const tr = document.createElement("tr");

    const score = fmt(log.threatScore || 0);
    const isPhish = log.phishingDetected === true;

    tr.innerHTML = `
      <td>${i + 1}</td>
      <td>${log.time || ""}</td>
      <td>
        <span class="tb-pill ${log.action === "block" ? "pill-block" : "pill-allow"}">
          ${log.action || ""}
        </span>
      </td>
      <td>
        <span class="tb-pill ${
          score >= 60 || isPhish ? "pill-score-high" : score >= 30 ? "pill-score-med" : "pill-score-low"
        }">
          ${score}
        </span>
      </td>
      <td>${getSourceLabel(log)}</td>
      <td>${log.visitedSite || "-"}</td>
      <td>${log.trackingDomain || "-"}</td>
    `;

    tbody.appendChild(tr);
  });
}

/* ------------------------------
   Stats (trackers set after renderTrackers)
------------------------------ */
async function loadStats() {
  const res = await sendMessageSafe({ type: "GET_STATS" });
  if (!res?.success) return;

  safeText("statTotalBlocked", res.totalBlocked || 0);
  safeText("statHighRisk", res.highThreat || 0);
}

/* ------------------------------
   High-risk alerts
------------------------------ */
function renderHighRisk(logs) {
  const tbody = document.querySelector("#alertsTable tbody");
  if (!tbody) return;

  tbody.innerHTML = "";

  const risky = (logs || []).filter((l) => {
    const score = Number(l.threatScore || 0);
    const isPhish = l.phishingDetected === true;
    return score >= 60 || isPhish;
  });

  if (!risky.length) {
    tbody.innerHTML = "<tr><td colspan='3' class='tb-empty'>No high-risk events yet.</td></tr>";
    return;
  }

  risky.slice(-20).reverse().forEach((log) => {
    const tr = document.createElement("tr");
    tr.classList.add("tb-high-row");

    const score = fmt(log.threatScore || 0);
    const domain = log.visitedSite || log.trackingDomain || "-";

    tr.innerHTML = `
      <td>${log.time || ""}</td>
      <td>${score}${log.phishingDetected ? " ⚠" : ""}</td>
      <td>${domain}</td>
    `;
    tbody.appendChild(tr);
  });
}

/* ------------------------------
   Phishing Events
------------------------------ */
function renderPhishingEvents(logs) {
  const tbody = document.querySelector("#phishingTable tbody");
  if (!tbody) return;

  tbody.innerHTML = "";

  const phish = (logs || []).filter((l) => l.phishingDetected === true);

  if (!phish.length) {
    tbody.innerHTML = "<tr><td colspan='4' class='tb-empty'>No phishing events yet.</td></tr>";
    return;
  }

  phish.slice(-30).reverse().forEach((log) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${log.time || ""}</td>
      <td>${fmt(log.threatScore || 0)}</td>
      <td>${log.phishingProvider || log.ruleId || "Threat Intel"}</td>
      <td>${log.trackingDomain || log.visitedSite || "-"}</td>
    `;
    tbody.appendChild(tr);
  });
}

/* ------------------------------
   Rules
------------------------------ */
function renderRules(rules) {
  currentRules = Array.isArray(rules) ? rules : [];
  const tbody = document.querySelector("#rulesTable tbody");
  if (!tbody) return;

  tbody.innerHTML = "";

  if (!currentRules.length) {
    tbody.innerHTML = "<tr><td colspan='4' class='tb-empty'>No custom rules defined.</td></tr>";
    return;
  }

  currentRules.forEach((r) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${r.id}</td>
      <td>${r.domain}</td>
      <td>${r.mode}</td>
      <td><button class="tb-btn small removeRule" data-id="${r.id}">Remove</button></td>
    `;
    tbody.appendChild(tr);
  });

  tbody.querySelectorAll(".removeRule").forEach((btn) =>
    btn.addEventListener("click", async () => {
      const id = Number(btn.dataset.id);
      await sendMessageSafe({ type: "DELETE_RULE", id });
      await loadRules();
    })
  );
}

async function loadRules() {
  const res = await sendMessageSafe({ type: "GET_RULES" });
  renderRules(res?.rules || []);
}

/* ------------------------------
   Cookies (Block/Allow) — FIXED TO MATCH SERVICE WORKER
   Uses: BLOCK_COOKIES_FOR_DOMAIN + ALLOW_COOKIES_FOR_DOMAIN
------------------------------ */
function cleanCookieDomain(domain) {
  if (!domain) return "";
  return String(domain).replace(/^\./, "").toLowerCase();
}

async function blockCookies(domain) {
  const res = await sendMessageSafe({ type: "BLOCK_COOKIES_FOR_DOMAIN", domain });
  if (!res?.success) {
    alert(res?.error || "Failed to block cookies");
    return;
  }
  await refreshAll();
}

async function allowCookies(domain) {
  const res = await sendMessageSafe({ type: "ALLOW_COOKIES_FOR_DOMAIN", domain });
  if (!res?.success) {
    alert(res?.error || "Failed to allow cookies");
    return;
  }
  await refreshAll();
}


function renderCookies(cookies) {
  cookieResults = Array.isArray(cookies) ? cookies : [];
  const tbody = document.querySelector("#cookieList");
  if (!tbody) return;

  tbody.innerHTML = "";

  if (!cookieResults.length) {
    tbody.innerHTML = "<tr><td colspan='5' class='tb-empty'>No cookies detected yet.</td></tr>";
    return;
  }

  cookieResults.forEach((c) => {
    const domain = cleanCookieDomain(c.domain);
    const tr = document.createElement("tr");

    tr.innerHTML = `
      <td>${c.name || ""}</td>
      <td>${domain}</td>
      <td>${c.status || ""}${c.policy ? ` — ${c.policy}` : ""}</td>
      <td>${c.expiryDate || ""}</td>
      <td>
        <button class="tb-btn small" data-act="block" data-domain="${domain}">Block</button>
        <button class="tb-btn small" data-act="allow" data-domain="${domain}">Allow</button>
      </td>
    `;
    tbody.appendChild(tr);
  });

  tbody.querySelectorAll("button[data-act]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const action = btn.dataset.act;
      const domain = btn.dataset.domain;
      if (!domain) return;

      if (action === "block") await blockCookies(domain);
      if (action === "allow") await allowCookies(domain);
    });
  });
}

async function loadLastCookies() {
  const res = await sendMessageSafe({ type: "GET_LAST_COOKIES" });
  if (!res?.success) return;
  renderCookies(res.cookies || []);
}

/* ------------------------------
   CSV Export
------------------------------ */
async function exportCSV() {
  const res = await sendMessageSafe({ type: "GET_LOGS" });
  if (!res?.success) {
    alert("Could not export logs (extension error).");
    return;
  }

  const logs = res.logs || [];
  if (!logs.length) {
    alert("No logs to export.");
    return;
  }

  let csv = "Time,Action,Score,Source,VisitedSite,TrackingDomain,URL,PhishingDetected,PhishingProvider\n";

  logs.forEach((l) => {
    const source = (l.phishingProvider || l.ruleId || "DNR");
    csv +=
      [
        csvEscape(l.time || ""),
        csvEscape(l.action || ""),
        l.threatScore != null ? l.threatScore : 0,
        csvEscape(source),
        csvEscape(l.visitedSite || ""),
        csvEscape(l.trackingDomain || ""),
        csvEscape(l.url || ""),
        l.phishingDetected ? "true" : "false",
        csvEscape(l.phishingProvider || "")
      ].join(",") + "\n";
  });

  const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);

  const a = document.createElement("a");
  a.href = url;
  a.download = "threatbarrier_logs.csv";
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);

  URL.revokeObjectURL(url);
}

/* ------------------------------
   Refresh All
------------------------------ */
async function refreshAll() {
  const ok = await enforceAuth({ closeTab: true });
  if (!ok) return;

  await loadStats();

  const res = await sendMessageSafe({ type: "GET_LOGS" });
  const logs = (res?.success && Array.isArray(res.logs)) ? res.logs : [];

  renderLogs(logs);
  renderHighRisk(logs);
  renderPhishingEvents(logs);

  const trackerCount = renderTrackers(logs);
  safeText("statTrackers", trackerCount || 0);

  await loadLastCookies();
}

/* ------------------------------
   Live cookie updates (optional)
------------------------------ */
chrome.runtime.onMessage.addListener((msg) => {
  if (msg?.type === "COOKIE_RESULTS") {
    renderCookies(msg.data || []);
  }

  if (msg?.type === "AUTH_CHANGED" && msg.loggedIn === false) {
    showLoggedOutOverlay();
    closeThisTab();
  }
});

/* ------------------------------
   Init
------------------------------ */
document.addEventListener("DOMContentLoaded", async () => {
  if (!$("loggedOutOverlay")) {
    const ov = document.createElement("div");
    ov.id = "loggedOutOverlay";
    ov.style.display = "none";
    ov.style.position = "fixed";
    ov.style.inset = "0";
    ov.style.background = "rgba(0,0,0,0.7)";
    ov.style.backdropFilter = "blur(6px)";
    ov.style.zIndex = "9999";
    ov.style.alignItems = "center";
    ov.style.justifyContent = "center";
    ov.style.color = "#fff";
    ov.style.fontFamily = "system-ui, sans-serif";
    ov.style.fontWeight = "800";
    ov.innerHTML = `<div style="padding:18px 22px;border:1px solid rgba(255,255,255,0.15);border-radius:14px;background:rgba(20,20,30,0.6);">
      Session ended. Please login again.
    </div>`;
    document.body.appendChild(ov);
  }

  const ok = await enforceAuth({ closeTab: true });
  if (!ok) return;

  await refreshAll();
  await loadRules();

  $("btnRefresh")?.addEventListener("click", refreshAll);

  $("btnClear")?.addEventListener("click", async () => {
    await sendMessageSafe({ type: "CLEAR_LOGS" });
    await refreshAll();
  });

  $("btnExport")?.addEventListener("click", exportCSV);

  $("ruleForm")?.addEventListener("submit", async (e) => {
    e.preventDefault();

    const domainInput = $("ruleDomain");
    const modeSelect = $("ruleMode");

    const domain = (domainInput?.value || "").trim();
    const mode = modeSelect?.value || "block";

    if (!domain) {
      alert("Please enter a domain, e.g. example.com");
      return;
    }

    const res = await sendMessageSafe({ type: "ADD_RULE", domain, mode });
    if (!res?.success) {
      alert(res?.error || "Rule could not be added.");
      return;
    }

    domainInput.value = "";
    await loadRules();
  });

  refreshTimer = setInterval(refreshAll, 3000);
  authTimer = setInterval(() => enforceAuth({ closeTab: true }), 2000);
});

// Keep SW awake (safe)
sendMessageSafe({ type: "PING" });
