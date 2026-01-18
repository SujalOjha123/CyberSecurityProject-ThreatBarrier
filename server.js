// ============================================================
// ThreatBarrier – Service Worker (MV3 + DNR) [STABLE + COOKIES]
// - Keeps: logs, rules, scan page summary, last cookies storage
// - Adds: Cookie Allow/Block per-domain (DNR modifyHeaders)
// ============================================================

console.log("[TB] Service worker loaded ✅");

/* ------------------------------
   Storage Keys
------------------------------ */
const LOGS_KEY = "tb_logs";
const RULES_KEY = "tb_rules";
const USER_KEY = "tb_user";

const LAST_COOKIES_KEY = "tb_last_cookies";
const LAST_COOKIES_URL_KEY = "tb_last_cookie_url";

// NEW: cookie policies
const COOKIE_RULES_KEY = "tb_cookie_rules"; // [{id, domain, mode:"block"}]
const COOKIE_RULE_ID_BASE = 900000; // keep away from your other DNR ids
const COOKIE_RULE_PRIORITY = 2000;

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
      resolve();
    });
  });

  return stateLoadPromise;
}

/* ------------------------------
   Helpers
------------------------------ */
function now() {
  return new Date().toTimeString().split(" ")[0];
}

function safeHostname(u) {
  try {
    return new URL(u).hostname || "";
  } catch {
    return "";
  }
}

function normalizeDomain(input) {
  const raw = String(input || "").trim().toLowerCase();
  if (!raw) return "";
  return raw
    .replace(/^https?:\/\//i, "")
    .replace(/\/.*$/, "")
    .replace(/^\.+/, "")
    .trim();
}

function isDomainMatch(host, ruleDomain) {
  // host: sub.a.com, ruleDomain: a.com -> true
  // host: a.com, ruleDomain: a.com -> true
  // host: evil-a.com, ruleDomain: a.com -> false
  if (!host || !ruleDomain) return false;
  const h = host.toLowerCase();
  const d = ruleDomain.toLowerCase();
  return h === d || h.endsWith("." + d);
}

function saveLogs() {
  chrome.storage.local.set({ [LOGS_KEY]: logs.slice(-1500) });
}

function saveRules() {
  chrome.storage.local.set({ [RULES_KEY]: customRules });
}

function saveCookieRules() {
  chrome.storage.local.set({ [COOKIE_RULES_KEY]: cookieRules });
}

async function isLoggedIn() {
  const { [USER_KEY]: u } = await chrome.storage.local.get([USER_KEY]);
  return !!(u && u.uid);
}

/* ------------------------------
   Stats + logging
------------------------------ */
function pushSecurityLog({ url, action, threatScore, ruleId, extra = {} }) {
  const trackingDomain = safeHostname(url) || extra.trackingDomain || "";
  const visitedSite = extra.visitedSite || "";

  logs.push({
    time: now(),
    action,
    threatScore: Number(threatScore || 0),
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

/* ------------------------------
   Cookie scanning
------------------------------ */
async function scanCookiesForTab(tabId) {
  try {
    const tab = await chrome.tabs.get(tabId);
    if (!tab?.url) return [];
    const url = tab.url;

    const cookies = await chrome.cookies.getAll({ url });

    // enrich with security status + policy
    const host = safeHostname(url);
    const blockedForHost = cookieRules.some((r) => r.mode === "block" && isDomainMatch(host, r.domain));

    const rows = cookies.map((c) => {
      const isSecure = !!c.secure;
      const sameSite = String(c.sameSite || "");
      const isHttpOnly = !!c.httpOnly;

      let status = "Secure ✓";
      if (!isSecure) status = "Insecure ✗";
      else if (sameSite === "no_restriction") status = "Weak SameSite ✗";
      else if (!isHttpOnly) status = "Weak HttpOnly ✗";

      return {
        name: c.name,
        domain: c.domain,
        status,
        expiryDate: c.session ? "Session" : (c.expirationDate ? new Date(c.expirationDate * 1000).toLocaleDateString() : "-"),
        policy: blockedForHost ? "Blocked (Set-Cookie stripped)" : "Allowed"
      };
    });

    // store for dashboard
    chrome.storage.local.set({
      [LAST_COOKIES_KEY]: rows,
      [LAST_COOKIES_URL_KEY]: url
    });

    // push live update to any open dashboards
    chrome.runtime.sendMessage({ type: "COOKIE_RESULTS", data: rows }, () => void chrome.runtime.lastError);

    return rows;
  } catch (e) {
    return [];
  }
}


/* ------------------------------
   Cookie Allow/Block via DNR
   - Block = remove Set-Cookie response header
   - Allow = remove rule
------------------------------ */
function cookieDnrRuleFor(domain, id) {
  // Use requestDomains so it matches subdomains too
  return {
    id,
    priority: COOKIE_RULE_PRIORITY,
    action: {
      type: "modifyHeaders",
      responseHeaders: [{ header: "set-cookie", operation: "remove" }]
    },
    condition: {
      requestDomains: [domain],
      resourceTypes: [
        "main_frame",
        "sub_frame",
        "xmlhttprequest",
        "script",
        "image",
        "font",
        "stylesheet",
        "other"
      ]
    }
  };
}

async function ensureCookieRuleInstalled(domain) {
  await ensureStateLoaded();

  const d = normalizeDomain(domain);
  if (!d) return { success: false, error: "Empty domain" };

  // if already exists, ok
  const existing = cookieRules.find((r) => r.domain === d && r.mode === "block");
  if (existing) return { success: true, id: existing.id };

  // pick next id
  const usedIds = new Set(cookieRules.map((r) => r.id));
  let next = COOKIE_RULE_ID_BASE;
  while (usedIds.has(next)) next++;

  const rule = cookieDnrRuleFor(d, next);

  await new Promise((resolve, reject) => {
    chrome.declarativeNetRequest.updateDynamicRules(
      { addRules: [rule], removeRuleIds: [] },
      () => {
        if (chrome.runtime.lastError) reject(new Error(chrome.runtime.lastError.message));
        else resolve();
      }
    );
  });

  cookieRules.push({ id: next, domain: d, mode: "block" });
  saveCookieRules();

  return { success: true, id: next };
}

async function removeCookieRule(domain) {
  await ensureStateLoaded();

  const d = normalizeDomain(domain);
  if (!d) return { success: false, error: "Empty domain" };

  const existing = cookieRules.find((r) => r.domain === d && r.mode === "block");
  if (!existing) return { success: true }; // already allowed

  await new Promise((resolve) => {
    chrome.declarativeNetRequest.updateDynamicRules(
      { addRules: [], removeRuleIds: [existing.id] },
      () => resolve()
    );
  });

  cookieRules = cookieRules.filter((r) => r.id !== existing.id);
  saveCookieRules();

  return { success: true };
}

/* ------------------------------
   OPTIONAL: your threat scoring (keep simple)
------------------------------ */
function threatScore(urlOrHost) {
  if (!urlOrHost) return 0;

  let score = 10;
  try {
    const u = new URL(urlOrHost);
    if (u.protocol === "http:") score += 20;
  } catch {}

  const low = String(urlOrHost).toLowerCase();
  if (low.includes("doubleclick") || low.includes("googlesyndication")) score += 40;
  if (low.includes("googletagmanager")) score += 20;
  if (low.includes("google-analytics") || low.includes("analytics")) score += 25;
  if (low.includes("facebook") || low.includes("pixel")) score += 30;

  return Math.max(0, Math.min(100, score));
}

/* ------------------------------
   DNR log listener (if you use it)
------------------------------ */
chrome.declarativeNetRequest.onRuleMatchedDebug?.addListener(async (info) => {
  // optional: keep it if you already use it. Not required for cookies.
  // console.log("[TB] DNR matched", info);
});

/* ------------------------------
   Message router (IMPORTANT)
------------------------------ */
function respondAsync(fn, sendResponse) {
  fn()
    .then((res) => sendResponse(res))
    .catch((e) => sendResponse({ success: false, error: String(e?.message || e) }));
  return true;
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  const type = msg?.type;

  switch (type) {
    case "PING":
      sendResponse({ success: true });
      return true;

    case "GET_STATS":
      return respondAsync(async () => {
        await ensureStateLoaded();
        return { success: true, ...getStats() };
      }, sendResponse);

    case "GET_LOGS":
      return respondAsync(async () => {
        await ensureStateLoaded();
        return { success: true, logs };
      }, sendResponse);

    case "CLEAR_LOGS":
      logs = [];
      saveLogs();
      sendResponse({ success: true });
      return true;

    case "GET_RULES":
      return respondAsync(async () => {
        await ensureStateLoaded();
        return { success: true, rules: customRules };
      }, sendResponse);

    // your existing ADD_RULE / DELETE_RULE can stay in your old file.
    // If you want, I can merge them in exactly—this answer focuses on cookie fix.

    case "GET_LAST_COOKIES":
      chrome.storage.local.get([LAST_COOKIES_KEY, LAST_COOKIES_URL_KEY], (d) => {
        sendResponse({
          success: true,
          cookies: d[LAST_COOKIES_KEY] || [],
          url: d[LAST_COOKIES_URL_KEY] || null
        });
      });
      return true;

    case "GET_COOKIE_RULES":
      return respondAsync(async () => {
        await ensureStateLoaded();
        return { success: true, cookieRules };
      }, sendResponse);

    case "BLOCK_COOKIES_FOR_DOMAIN":
      return respondAsync(async () => {
        if (!(await isLoggedIn())) return { success: false, error: "Not logged in" };
        return await ensureCookieRuleInstalled(msg.domain);
      }, sendResponse);

    case "ALLOW_COOKIES_FOR_DOMAIN":
      return respondAsync(async () => {
        if (!(await isLoggedIn())) return { success: false, error: "Not logged in" };
        return await removeCookieRule(msg.domain);
      }, sendResponse);

    case "SCAN_PAGE":
      return respondAsync(async () => {
        if (!(await isLoggedIn())) return { success: false, error: "Not logged in" };
        await ensureStateLoaded();

        const tabId = Number(msg.tabId);
        const url = msg.url || "";
        const finalScore = threatScore(url);

        // log a scan event (allow by default here)
        pushSecurityLog({
          url,
          action: "allow",
          threatScore: finalScore,
          ruleId: "Local Scan",
          extra: {
            visitedSite: safeHostname(url),
            trackingDomain: safeHostname(url)
          }
        });

        const cookies = await scanCookiesForTab(tabId);

        // cookie score (simple)
        let cookieScore = 100;
        const trackingCount = cookies.filter((c) => String(c.status).toLowerCase().includes("tracking")).length;
        const insecureCount = cookies.filter((c) => String(c.status).toLowerCase().includes("insecure")).length;
        const weakSameSite = cookies.filter((c) => String(c.status).toLowerCase().includes("samesite")).length;

        cookieScore -= trackingCount * 15;
        cookieScore -= insecureCount * 10;
        cookieScore -= weakSameSite * 5;
        cookieScore = Math.max(0, Math.min(100, cookieScore));

        return {
          success: true,
          summary: {
            url,
            threatScore: finalScore,
            cookieScore,
            cookies,
            blockedRecent: logs.filter((l) => l.action === "block").slice(-5).map((l) => l.trackingDomain || safeHostname(l.url)),
            phishingDetected: false,
            phishingProvider: null
          }
        };
      }, sendResponse);

    default:
      // IMPORTANT: don't throw errors for unknown messages
      sendResponse({ success: false, error: "Unknown message type" });
      return true;
  }
});

