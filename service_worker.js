// ============================================================
// ThreatBarrier – Service Worker (MV3 + DNR) [FULL WORKING FILE]
// - DNR logs (visitedSite + trackingDomain)
// - Scan Page: local scoring + threat intel (OpenPhish free, URLhaus optional, VT optional)
// - Cookie Inspector: scans cookies on SCAN_PAGE
// - Cookie Allow/Block (per-domain): MV3 DNR modifyHeaders (removes Cookie + Set-Cookie)
// - Clears existing cookies on Block so user sees immediate effect
// - No Firebase CDN imports (MV3 CSP safe)
// ============================================================

console.log("[TB] Service worker loaded ✅");

// ------------------------------
// Storage Keys
// ------------------------------
const LOGS_KEY = "tb_logs";
const RULES_KEY = "tb_rules";
const USER_KEY = "tb_user"; // {uid,email} set by popup after login

const LAST_COOKIES_KEY = "tb_last_cookies";
const LAST_COOKIES_URL_KEY = "tb_last_cookie_url";

// Cookie block rules (dynamic DNR rules we manage)
const COOKIE_RULES_KEY = "tb_cookie_rules"; // [{ domain:"example.com", ruleId: 900001 }]
const COOKIE_RULE_PRIORITY = 2000;

// ------------------------------
// In-memory state
// ------------------------------
let logs = [];
let customRules = [];
let cookieRules = [];

let stateLoaded = false;
let stateLoadPromise = null;

function ensureStateLoaded() {
  if (stateLoaded) return Promise.resolve();
  if (stateLoadPromise) return stateLoadPromise;

  stateLoadPromise = new Promise((resolve) => {
    chrome.storage.local.get([LOGS_KEY, RULES_KEY, COOKIE_RULES_KEY], (d) => {
      logs = Array.isArray(d[LOGS_KEY]) ? d[LOGS_KEY] : [];
      customRules = Array.isArray(d[RULES_KEY]) ? d[RULES_KEY] : [];
      cookieRules = Array.isArray(d[COOKIE_RULES_KEY]) ? d[COOKIE_RULES_KEY] : [];
      stateLoaded = true;
      console.log("[TB] Loaded logs:", logs.length, "rules:", customRules.length, "cookieRules:", cookieRules.length);
      resolve();
    });
  });

  return stateLoadPromise;
}

// ------------------------------
// Helpers
// ------------------------------
function now() {
  return new Date().toTimeString().split(" ")[0];
}

function saveLogs() {
  // keep last 1500
  chrome.storage.local.set({ [LOGS_KEY]: logs.slice(-1500) });
}

function saveRules() {
  chrome.storage.local.set({ [RULES_KEY]: customRules });
}

function saveCookieRules() {
  chrome.storage.local.set({ [COOKIE_RULES_KEY]: cookieRules });
}

function safeHostname(u) {
  try {
    return new URL(u).hostname || "";
  } catch {
    return "";
  }
}

function safeOriginHostname(origin) {
  try {
    return new URL(origin).hostname || "";
  } catch {
    return "";
  }
}

function normalizeDomain(input) {
  return String(input || "")
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//i, "")
    .replace(/\/.*$/, "")
    .replace(/^\.+/, "");
}

async function isLoggedIn() {
  const { [USER_KEY]: tb_user } = await chrome.storage.local.get([USER_KEY]);
  return !!(tb_user && tb_user.uid);
}

async function getDynamicRules() {
  return await new Promise((resolve) => {
    chrome.declarativeNetRequest.getDynamicRules((r) => resolve(r || []));
  });
}

async function updateDynamicRules({ addRules = [], removeRuleIds = [] }) {
  await new Promise((resolve, reject) => {
    chrome.declarativeNetRequest.updateDynamicRules({ addRules, removeRuleIds }, () => {
      if (chrome.runtime.lastError) reject(new Error(chrome.runtime.lastError.message));
      else resolve();
    });
  });
}

// ------------------------------
// Tab -> Visited Site cache
// ------------------------------
const tabTopSiteCache = new Map(); // tabId -> { visitedSite, ts }
const TAB_CACHE_TTL_MS = 60 * 1000;

function setTabVisitedSite(tabId, visitedSite) {
  if (typeof tabId !== "number" || tabId < 0) return;
  if (!visitedSite) return;
  tabTopSiteCache.set(tabId, { visitedSite, ts: Date.now() });
}

function getTabVisitedSite(tabId) {
  const v = tabTopSiteCache.get(tabId);
  if (!v) return "";
  if (Date.now() - v.ts > TAB_CACHE_TTL_MS) {
    tabTopSiteCache.delete(tabId);
    return "";
  }
  return v.visitedSite || "";
}

// keep visited site correct
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "loading" && tab?.url) {
    const site = safeHostname(tab.url);
    if (site) setTabVisitedSite(tabId, site);
  }
});

// ------------------------------
// Tracker patterns (simple scoring)
// ------------------------------
const TRACKER_PATTERNS = {
  analytics: ["google-analytics", "analytics.google", "matomo", "mixpanel", "segment.io", "amplitude", "hotjar"],
  ads: ["doubleclick", "googlesyndication", "googleadservices", "googleads", "adservice", "adnxs", "criteo", "taboola", "outbrain"],
  social: ["facebook.com", "connect.facebook.net", "fbcdn.net", "twitter.com", "t.co", "tiktok.com", "linkedin.com", "instagram.com"],
  loader: ["googletagmanager.com", "cdn.segment.com"],
  fingerprinting: ["fingerprintjs", "perimeterx", "px-cloud.net", "deviceid"]
};

function getTrackerCategory(host) {
  if (!host) return null;
  const h = String(host).toLowerCase();
  for (const [cat, pats] of Object.entries(TRACKER_PATTERNS)) {
    if (pats.some((p) => h.includes(p))) return cat;
  }
  if (h.includes("track") || h.includes("pixel") || h.includes("analytics")) return "generic";
  return null;
}

function threatScore(urlOrHost) {
  if (!urlOrHost) return 0;

  let host = "";
  let score = 10;

  try {
    const u = new URL(urlOrHost);
    host = u.hostname || "";
    if (u.protocol === "http:") score += 20;
  } catch {
    host = String(urlOrHost).toLowerCase();
  }

  const cat = getTrackerCategory(host);
  if (cat === "analytics") score += 25;
  else if (cat === "ads") score += 40;
  else if (cat === "social") score += 30;
  else if (cat === "loader") score += 20;
  else if (cat === "fingerprinting") score += 50;
  else if (cat === "generic") score += 20;

  const low = String(urlOrHost).toLowerCase();
  if (low.includes("pixel")) score += 5;
  if (low.includes("track")) score += 5;

  return Math.max(0, Math.min(100, score));
}

// ------------------------------
// Logs push (includes visitedSite + trackingDomain)
// ------------------------------
function pushSecurityLog({ url, action, threatScore: score, ruleId, extra = {} }) {
  const trackingDomain = safeHostname(url) || (extra.trackingDomain || "");
  const visitedSite = extra.visitedSite || "";

  logs.push({
    time: now(),
    action, // block/allow
    threatScore: score || 0,
    ruleId: ruleId || "",
    url: url || "",
    visitedSite,
    trackingDomain,
    phishingDetected: !!extra.phishingDetected,
    phishingProvider: extra.phishingProvider || null
  });

  saveLogs();
}

function getStats() {
  let totalBlocked = 0;
  let highThreat = 0;
  const trackers = new Set();

  for (const l of logs) {
    if (l.action === "block") totalBlocked++;
    if ((l.threatScore || 0) >= 60 || l.phishingDetected === true) highThreat++;
    if (l.trackingDomain) trackers.add(String(l.trackingDomain).toLowerCase());
  }

  return { totalBlocked, highThreat, trackersSeen: trackers.size };
}

// ============================================================
// Threat Intel (Scan-only)
// ============================================================

// NOTE: API keys inside extension can be extracted. For coursework demo only.

// VirusTotal (optional)
const VT_API_KEY = ""; // recommended: leave blank

// OpenPhish (free feed)
const OPENPHISH_FEED_URL =
  "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt";

let openphishSet = new Set();
let openphishLoadedAt = 0;
const OPENPHISH_REFRESH_MS = 12 * 60 * 60 * 1000;

// URLhaus (optional)
const URLHAUS_AUTH_KEY = ""; // optional
const URLHAUS_QUERY_URL = "https://urlhaus-api.abuse.ch/v1/url/";

// cache
const intelCache = new Map(); // key -> {detected, provider, matches, ts}
const INTEL_TTL_MS = 10 * 60 * 1000;

function normalizeUrl(u) {
  try {
    return new URL(u).toString().replace(/\/$/, "");
  } catch {
    return String(u || "").trim().replace(/\/$/, "");
  }
}

function intelCacheGet(key) {
  const v = intelCache.get(key);
  if (!v) return null;
  if (Date.now() - v.ts > INTEL_TTL_MS) {
    intelCache.delete(key);
    return null;
  }
  return v;
}

function intelCacheSet(key, payload) {
  intelCache.set(key, { ...payload, ts: Date.now() });
}

// ---- OpenPhish
async function refreshOpenPhishFeedIfNeeded() {
  const needsRefresh =
    openphishSet.size === 0 || (Date.now() - openphishLoadedAt) > OPENPHISH_REFRESH_MS;
  if (!needsRefresh) return;

  try {
    const r = await fetch(OPENPHISH_FEED_URL, { method: "GET" });
    const text = await r.text();
    const lines = text
      .split("\n")
      .map((s) => s.trim())
      .filter((s) => s && !s.startsWith("#"));

    openphishSet = new Set(lines.map((x) => x.replace(/\/$/, "")));
    openphishLoadedAt = Date.now();
    console.log("[TB] OpenPhish feed loaded:", openphishSet.size);
  } catch (e) {
    console.warn("[TB] OpenPhish feed fetch failed:", e);
  }
}

async function checkOpenPhish(url) {
  await refreshOpenPhishFeedIfNeeded();
  const key = normalizeUrl(url);
  const detected = openphishSet.has(key);
  return {
    detected,
    provider: "OpenPhish",
    matches: detected ? [{ url: key, source: "openphish_feed" }] : []
  };
}

// ---- URLhaus
async function checkURLhaus(url) {
  if (!URLHAUS_AUTH_KEY) return { detected: false, provider: "URLhaus", matches: [] };

  try {
    const body = new URLSearchParams({ url });
    const r = await fetch(URLHAUS_QUERY_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Auth-Key": URLHAUS_AUTH_KEY
      },
      body
    });

    const data = await r.json().catch(() => ({}));
    const detected = data?.query_status === "ok";
    return { detected: !!detected, provider: "URLhaus", matches: detected ? [data] : [] };
  } catch (e) {
    console.warn("[TB] URLhaus fetch failed:", e);
    return { detected: false, provider: "URLhaus", matches: [] };
  }
}

// ---- VirusTotal v3 (optional)
async function vtSubmitUrl(url) {
  const form = new URLSearchParams();
  form.set("url", url);

  const r = await fetch("https://www.virustotal.com/api/v3/urls", {
    method: "POST",
    headers: {
      "x-apikey": VT_API_KEY,
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body: form
  });

  const data = await r.json().catch(() => ({}));
  const analysisId = data?.data?.id;
  if (!analysisId) throw new Error("VT submit failed (no analysis id)");
  return analysisId;
}

async function vtFetchAnalysis(analysisId) {
  const r = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
    method: "GET",
    headers: { "x-apikey": VT_API_KEY }
  });
  const data = await r.json().catch(() => ({}));
  const stats = data?.data?.attributes?.stats || {};
  return { raw: data, stats };
}

async function checkVirusTotal(url) {
  if (!VT_API_KEY) return { detected: false, provider: "VirusTotal", matches: [] };

  const key = "vt:" + normalizeUrl(url);
  const cached = intelCacheGet(key);
  if (cached) return cached;

  try {
    const analysisId = await vtSubmitUrl(url);
    await new Promise((r) => setTimeout(r, 1200));
    const analysis = await vtFetchAnalysis(analysisId);

    const mal = Number(analysis.stats.malicious || 0);
    const sus = Number(analysis.stats.suspicious || 0);
    const detected = (mal + sus) > 0;

    const res = {
      detected,
      provider: "VirusTotal",
      matches: [{ analysis_id: analysisId, stats: analysis.stats }]
    };

    intelCacheSet(key, res);
    return res;
  } catch (e) {
    const res = { detected: false, provider: "VirusTotal", matches: [{ error: String(e?.message || e) }] };
    intelCacheSet(key, res);
    return res;
  }
}

// ---- Unified
async function checkThreatIntel(url) {
  const key = "intel:" + normalizeUrl(url);
  const cached = intelCacheGet(key);
  if (cached) return cached;

  const vt = await checkVirusTotal(url);
  if (vt.detected) {
    intelCacheSet(key, vt);
    return vt;
  }

  const op = await checkOpenPhish(url);
  if (op.detected) {
    intelCacheSet(key, op);
    return op;
  }

  const uh = await checkURLhaus(url);
  intelCacheSet(key, uh);
  return uh;
}

// ============================================================
// Cookie Inspector (SCAN_PAGE only)
// ============================================================
async function scanCookiesForTab(tabId) {
  await ensureStateLoaded();

  return new Promise((resolve) => {
    chrome.tabs.get(tabId, (tab) => {
      if (chrome.runtime.lastError) {
        console.error("[TB] tabs.get failed:", chrome.runtime.lastError.message);
        resolve([]);
        return;
      }

      if (!tab?.url || !/^https?:\/\//i.test(tab.url)) {
        console.warn("[TB] Cookie scan skipped (invalid tab url):", tab?.url);
        resolve([]);
        return;
      }

      const targetUrl = tab.url;

      chrome.cookies.getAll({ url: targetUrl }, (cookiesForUrl) => {
        if (chrome.runtime.lastError) {
          console.error("[TB] cookies.getAll failed:", chrome.runtime.lastError.message, targetUrl);
          resolve([]);
          return;
        }

        const analysed = analyseCookies(Array.isArray(cookiesForUrl) ? cookiesForUrl : []);
        persistAndBroadcastCookies(analysed, targetUrl);
        resolve(analysed);
      });
    });
  });
}

function analyseCookies(cookies) {
  return (cookies || []).map((c) => {
    let status = "Secure ✔";
    const exp = c.expirationDate ? new Date(c.expirationDate * 1000).toLocaleDateString() : "Session";

    const sameSite = (c.sameSite || "").toLowerCase();
    if (!c.secure) status = "Insecure ✖";
    if (!sameSite || sameSite === "no_restriction" || sameSite === "unspecified") status = "Weak SameSite ✖";

    const d = (c.domain || "").toLowerCase();
    if (d.includes("track") || d.includes("ads") || d.includes("doubleclick")) status = "Tracking Cookie ⚠";

    const cleanDomain = normalizeDomain(d);
    const blocked = cookieRules.some((r) => r.domain === cleanDomain);
    const policy = blocked ? "Blocked (Cookie/Set-Cookie stripped)" : "Allowed";

    return { name: c.name, domain: c.domain, status, expiryDate: exp, policy };
  });
}

function persistAndBroadcastCookies(analysed, url) {
  chrome.storage.local.set({
    [LAST_COOKIES_KEY]: analysed,
    [LAST_COOKIES_URL_KEY]: url || ""
  });

  chrome.runtime.sendMessage({ type: "COOKIE_RESULTS", data: analysed }, () => {
    void chrome.runtime.lastError;
  });
}

// ============================================================
// Cookie Allow/Block (MV3 DNR modifyHeaders)
// - Block: remove Cookie (request) and Set-Cookie (response)
// - Allow: remove our dynamic rule
// ============================================================
function cookieDnrRule(domain, ruleId) {
  return {
    id: ruleId,
    priority: COOKIE_RULE_PRIORITY,
    action: {
      type: "modifyHeaders",
      requestHeaders: [{ header: "cookie", operation: "remove" }],
      responseHeaders: [{ header: "set-cookie", operation: "remove" }]
    },
    condition: {
      requestDomains: [domain],
      resourceTypes: ["main_frame", "sub_frame", "xmlhttprequest", "script", "image", "stylesheet", "font", "other"]
    }
  };
}

async function addCookieBlock(domainRaw) {
  await ensureStateLoaded();

  const domain = normalizeDomain(domainRaw);
  if (!domain) return { success: false, error: "Empty domain" };

  const existing = cookieRules.find((r) => r.domain === domain);
  if (existing) return { success: true, ruleId: existing.ruleId, note: "Already blocked" };

  const dyn = await getDynamicRules();
  let maxId = 0;
  dyn.forEach((r) => { if (typeof r.id === "number" && r.id > maxId) maxId = r.id; });
  customRules.forEach((r) => { if (typeof r.id === "number" && r.id > maxId) maxId = r.id; });
  cookieRules.forEach((r) => { if (typeof r.ruleId === "number" && r.ruleId > maxId) maxId = r.ruleId; });

  const ruleId = maxId + 1;

  await updateDynamicRules({ addRules: [cookieDnrRule(domain, ruleId)], removeRuleIds: [] });

  cookieRules.push({ domain, ruleId });
  saveCookieRules();

  return { success: true, ruleId };
}

async function removeCookieBlock(domainRaw) {
  await ensureStateLoaded();

  const domain = normalizeDomain(domainRaw);
  if (!domain) return { success: false, error: "Empty domain" };

  const existing = cookieRules.find((r) => r.domain === domain);
  if (!existing) return { success: true, note: "No cookie block found" };

  await updateDynamicRules({ addRules: [], removeRuleIds: [existing.ruleId] });

  cookieRules = cookieRules.filter((r) => r.domain !== domain);
  saveCookieRules();

  return { success: true };
}

// ✅ Important improvement: clear existing cookies so block is visible immediately
async function clearCookiesForDomain(domainRaw) {
  const domain = normalizeDomain(domainRaw);
  if (!domain) return;

  const all = await new Promise((resolve) => chrome.cookies.getAll({}, (c) => resolve(c || [])));

  const targets = all.filter((c) => {
    const cd = normalizeDomain(c.domain);
    return cd === domain || cd.endsWith("." + domain);
  });

  await Promise.all(
    targets.map((c) => {
      const proto = c.secure ? "https://" : "http://";
      const host = c.domain.startsWith(".") ? c.domain.slice(1) : c.domain;
      const url = proto + host + (c.path || "/");
      return new Promise((resolve) => chrome.cookies.remove({ url, name: c.name }, () => resolve()));
    })
  );
}

// ============================================================
// DNR Log Listener
// ============================================================
if (chrome.declarativeNetRequest.onRuleMatchedDebug) {
  chrome.declarativeNetRequest.onRuleMatchedDebug.addListener((info) => {
    try {
      const reqUrl = info.request?.url || "";
      const actionType = info.rule?.action?.type || "allow";
      const tabId = info.request?.tabId;

      const trackingDomain = safeHostname(reqUrl);
      let visitedSite = getTabVisitedSite(tabId);

      if (!visitedSite && info.request?.initiator) {
        visitedSite = safeOriginHostname(info.request.initiator);
      }

      if (!visitedSite && typeof tabId === "number" && tabId >= 0) {
        chrome.tabs.get(tabId, (tab) => {
          if (tab?.url) setTabVisitedSite(tabId, safeHostname(tab.url));
        });
      }

      pushSecurityLog({
        url: reqUrl,
        action: actionType === "block" ? "block" : "allow",
        threatScore: threatScore(reqUrl),
        ruleId: info.rule?.id || "DNR",
        extra: { visitedSite, trackingDomain }
      });
    } catch (e) {
      console.error("[TB] onRuleMatchedDebug error:", e);
    }
  });
}

// ============================================================
// Message Handler
// ============================================================
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg || !msg.type) {
    sendResponse({ success: false, error: "Missing msg.type" });
    return false;
  }

  const respondAsync = (fn) => {
    (async () => {
      try {
        const out = await fn();
        sendResponse(out);
      } catch (e) {
        sendResponse({ success: false, error: e?.message || String(e) });
      }
    })();
    return true; // keep channel open
  };

  switch (msg.type) {
    case "PING":
      sendResponse({ success: true, from: "service_worker" });
      return true;

    case "AUTH_STATUS":
      return respondAsync(async () => {
        return { success: true, loggedIn: await isLoggedIn() };
      });

    // -----------------------
    // SCAN_PAGE
    // -----------------------
    case "SCAN_PAGE":
      return respondAsync(async () => {
        await ensureStateLoaded();

        if (!msg.tabId || !msg.url) return { success: false, error: "Missing tabId or url" };

        const url = msg.url;
        let finalScore = threatScore(url);

        const intel = await checkThreatIntel(url);
        const phishingDetected = !!intel.detected;

        if (phishingDetected) finalScore = Math.max(finalScore, 90);

        const visitedSite = safeHostname(url);

        pushSecurityLog({
          url,
          action: phishingDetected ? "block" : "allow",
          threatScore: finalScore,
          ruleId: intel.provider || "Threat Intel",
          extra: {
            visitedSite,
            trackingDomain: safeHostname(url),
            phishingDetected,
            phishingProvider: intel.provider || "Threat Intel"
          }
        });

        const cookies = await scanCookiesForTab(msg.tabId);

        let trackingCount = 0, insecureCount = 0, weakSameSiteCount = 0;
        cookies.forEach((c) => {
          const st = String(c.status || "");
          if (st.includes("Tracking")) trackingCount++;
          if (st.includes("Insecure")) insecureCount++;
          if (st.includes("Weak SameSite")) weakSameSiteCount++;
        });

        let cookieScore = 100;
        cookieScore -= trackingCount * 15;
        cookieScore -= insecureCount * 10;
        cookieScore -= weakSameSiteCount * 5;
        cookieScore = Math.max(0, Math.min(100, cookieScore));

        const blockedRecent = logs
          .filter((l) => l.action === "block")
          .slice(-5)
          .map((l) => l.trackingDomain || safeHostname(l.url) || l.url);

        return {
          success: true,
          summary: {
            url,
            threatScore: finalScore,
            cookieScore,
            cookies,
            blockedRecent,
            phishingDetected,
            phishingProvider: intel.provider || "Threat Intel",
            phishingMatches: (intel.matches || []).slice(0, 3)
          }
        };
      });

    // -----------------------
    // GET_PAGE_SUMMARY
    // -----------------------
    case "GET_PAGE_SUMMARY":
      return respondAsync(async () => {
        await ensureStateLoaded();

        const stats = getStats();
        const pageThreatScore = msg.url ? threatScore(msg.url) : null;

        const blockedRecent = logs
          .filter((l) => l.action === "block")
          .slice(-5)
          .map((l) => l.trackingDomain || safeHostname(l.url) || l.url);

        return { success: true, summary: { ...stats, pageThreatScore, blockedRecent } };
      });

    case "GET_STATS":
      return respondAsync(async () => {
        await ensureStateLoaded();
        return { success: true, ...getStats() };
      });

    case "GET_LOGS":
      return respondAsync(async () => {
        await ensureStateLoaded();
        return { success: true, logs };
      });

    case "CLEAR_LOGS":
      logs = [];
      saveLogs();
      sendResponse({ success: true });
      return true;

    case "GET_LAST_COOKIES":
      chrome.storage.local.get([LAST_COOKIES_KEY, LAST_COOKIES_URL_KEY], (d) => {
        sendResponse({
          success: true,
          cookies: d[LAST_COOKIES_KEY] || [],
          url: d[LAST_COOKIES_URL_KEY] || null
        });
      });
      return true;

    // -----------------------
    // Cookie Allow/Block API for Dashboard buttons
    // -----------------------
    case "BLOCK_COOKIES_FOR_DOMAIN":
      return respondAsync(async () => {
        const out = await addCookieBlock(msg.domain);
        // clear existing cookies so it looks like it worked immediately
        await clearCookiesForDomain(msg.domain);
        return out;
      });

    case "ALLOW_COOKIES_FOR_DOMAIN":
      return respondAsync(async () => {
        return await removeCookieBlock(msg.domain);
      });

    case "GET_COOKIE_BLOCK_RULES":
      return respondAsync(async () => {
        await ensureStateLoaded();
        return { success: true, rules: cookieRules };
      });

    // -----------------------
    // Custom firewall rules (Allow/Block)
    // -----------------------
    case "GET_RULES":
      return respondAsync(async () => {
        await ensureStateLoaded();
        return { success: true, rules: customRules };
      });

    case "ADD_RULE":
      return respondAsync(async () => {
        await ensureStateLoaded();

        let rawDomain = (msg.domain || "").trim();
        const mode = msg.mode === "allow" ? "allow" : "block";
        if (!rawDomain) return { success: false, error: "Empty domain" };

        const domain = normalizeDomain(rawDomain);
        const urlFilter = "||" + domain + "^";

        const existing = await getDynamicRules();

        let maxId = 0;
        existing.forEach((r) => { if (typeof r.id === "number" && r.id > maxId) maxId = r.id; });
        customRules.forEach((r) => { if (typeof r.id === "number" && r.id > maxId) maxId = r.id; });
        cookieRules.forEach((r) => { if (typeof r.ruleId === "number" && r.ruleId > maxId) maxId = r.ruleId; });

        const nextId = maxId + 1;

        const dnrRule = {
          id: nextId,
          priority: 1000,
          action: { type: mode === "allow" ? "allow" : "block" },
          condition: {
            urlFilter,
            resourceTypes: ["main_frame", "sub_frame", "script", "image", "xmlhttprequest", "other"]
          }
        };

        await updateDynamicRules({ addRules: [dnrRule], removeRuleIds: [] });

        customRules.push({ id: nextId, domain, mode });
        saveRules();

        return { success: true };
      });

    case "DELETE_RULE":
      return respondAsync(async () => {
        await ensureStateLoaded();

        const id = Number(msg.id);
        if (!id) return { success: false, error: "Invalid rule id" };

        await updateDynamicRules({ addRules: [], removeRuleIds: [id] });

        customRules = customRules.filter((r) => r.id !== id);
        saveRules();

        return { success: true };
      });

    default:
      sendResponse({ success: false, error: "Unknown message type: " + msg.type });
      return true;
  }
});

// ------------------------------------------------------------
// Install
// ------------------------------------------------------------
chrome.runtime.onInstalled.addListener(() => {
  console.log("[TB] ThreatBarrier installed (MV3).");
  ensureStateLoaded().catch(() => {});
});
