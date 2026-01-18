// popup.js (FULL CLEAN VERSION - copy/paste whole file)

import {
  auth,
  signInWithEmailAndPassword,
  createUserWithEmailAndPassword,
  sendEmailVerification,
  signOut,
  onAuthStateChanged
} from "./firebase-auth.bundle.js";

/* ------------------------------
   Helpers
------------------------------ */
function getActiveTab() {
  return new Promise((resolve) => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => resolve(tabs?.[0] || null));
  });
}

function sendMessageSafe(msg) {
  return new Promise((resolve) => {
    try {
      chrome.runtime.sendMessage(msg, (res) => {
        if (chrome.runtime.lastError) {
          return resolve({ success: false, error: chrome.runtime.lastError.message });
        }
        resolve(res || { success: false, error: "No response" });
      });
    } catch (e) {
      resolve({ success: false, error: String(e?.message || e) });
    }
  });
}

function $(id) {
  return document.getElementById(id);
}

function setText(id, text) {
  const el = $(id);
  if (el) el.textContent = text;
}

function safeShowAlert(level, message) {
  const box = $("alert-container");
  if (!box) return;

  const d = document.createElement("div");
  d.className = `alert alert-${level}`;
  d.textContent = message;

  box.appendChild(d);
  setTimeout(() => d.remove(), 4500);
}

function showLoginUI() {
  const lf = $("loginForm");
  const ac = $("appContent");
  if (lf) lf.style.display = "block";
  if (ac) ac.style.display = "none";
}

function showAppUI() {
  const lf = $("loginForm");
  const ac = $("appContent");
  if (lf) lf.style.display = "none";
  if (ac) ac.style.display = "block";
}

function normalizeDomainFromUrl(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return "";
  }
}

/* ------------------------------
  Virus Total
------------------------------ */

document.getElementById("btnVirusTotal").addEventListener("click", () => {
  chrome.tabs.create({
    url: chrome.runtime.getURL("virustotal/virustotal.html")
  });
});

/* ------------------------------
   Render summary (Threat + Cookies)
------------------------------ */
function renderPageSummary(summary = {}) {
  // ---------- Threat score ----------
  const rawScore =
    typeof summary.threatScore === "number"
      ? summary.threatScore
      : typeof summary.pageThreatScore === "number"
      ? summary.pageThreatScore
      : 0;

  const score = Math.max(0, Math.min(100, rawScore));
  setText("threat-score", `Score: ${score}/100`);

  // ---------- Threat level ----------
  const threatLevel = score >= 70 ? "High" : score >= 40 ? "Medium" : "Low";
  setText("threatLevelLabel", threatLevel);

  // ---------- Cookie status ----------
  const cookieStatus =
    typeof summary.cookieScore === "number"
      ? summary.cookieScore >= 80
        ? "Safe"
        : summary.cookieScore >= 50
        ? "Medium"
        : "Risky"
      : "Not scanned";

  setText("cookieStatusLabel", cookieStatus);

  // ---------- Recently blocked ----------
  const ul = $("blockedList");
  const items = Array.isArray(summary.blockedRecent) ? summary.blockedRecent : [];

  if (ul) {
    ul.innerHTML = "";
    if (!items.length) {
      ul.innerHTML = `<li class="placeholder">No trackers blocked yet.</li>`;
    } else {
      items.slice(0, 5).forEach((item) => {
        const li = document.createElement("li");
        li.textContent = item;
        ul.appendChild(li);
      });
    }
  }
}

/* ------------------------------
   Actions
------------------------------ */
async function refreshSummary() {
  const tab = await getActiveTab();
  if (!tab?.url) return;

  const res = await sendMessageSafe({ type: "GET_PAGE_SUMMARY", url: tab.url });
  if (res?.success && res.summary) renderPageSummary(res.summary);
}

async function scanPage() {
  const tab = await getActiveTab();
  if (!tab?.id || !tab.url) {
    safeShowAlert("high", "No active website tab found.");
    return;
  }

  const res = await sendMessageSafe({ type: "SCAN_PAGE", tabId: tab.id, url: tab.url });
  if (!res?.success) {
    safeShowAlert("high", res?.error || "Scan failed");
    return;
  }

  renderPageSummary(res.summary || {});
  safeShowAlert("low", "Scan complete ✅");
}

async function blockCookiesForThisSite() {
  const tab = await getActiveTab();
  const domain = normalizeDomainFromUrl(tab?.url || "");
  if (!domain) {
    safeShowAlert("high", "No active site found.");
    return;
  }

  const res = await sendMessageSafe({ type: "BLOCK_COOKIES_FOR_DOMAIN", domain });
  if (!res?.success) {
    safeShowAlert("high", res?.error || "Could not block cookies");
    return;
  }

  safeShowAlert("medium", `Cookies blocked for: ${domain}`);
  await scanPage();
}

async function allowCookiesForThisSite() {
  const tab = await getActiveTab();
  const domain = normalizeDomainFromUrl(tab?.url || "");
  if (!domain) {
    safeShowAlert("high", "No active site found.");
    return;
  }

  const res = await sendMessageSafe({ type: "ALLOW_COOKIES_FOR_DOMAIN", domain });
  if (!res?.success) {
    safeShowAlert("high", res?.error || "Could not allow cookies");
    return;
  }

  safeShowAlert("low", `Cookies allowed for: ${domain}`);
  await scanPage();
}

function openTechLookup() {
  // Ensure your techlookup path is correct in the extension
  chrome.tabs.create({ url: chrome.runtime.getURL("techlookup/techlookup.html") });
}

/* ------------------------------
   Auth wiring + UI events
------------------------------ */
document.addEventListener("DOMContentLoaded", () => {
  // login
  $("loginBtn")?.addEventListener("click", async () => {
    const email = ($("email")?.value || "").trim();
    const pass = ($("password")?.value || "").trim();
    if (!email || !pass) return safeShowAlert("high", "Enter email + password");

    try {
      const cred = await signInWithEmailAndPassword(auth, email, pass);

      if (!cred?.user?.emailVerified) {
        safeShowAlert("high", "Please verify your email before login.");
        await signOut(auth);
        return;
      }

      // store user for service worker gating (if you use gating)
      chrome.storage.local.set({ tb_user: { uid: cred.user.uid, email: cred.user.email } });

      safeShowAlert("low", "Logged in ✅");
      showAppUI();
      refreshSummary();
    } catch (e) {
      safeShowAlert("high", e?.message || "Login failed");
    }
  });

  // signup
  $("signupBtn")?.addEventListener("click", async () => {
    const email = ($("email")?.value || "").trim();
    const pass = ($("password")?.value || "").trim();
    if (!email || !pass) return safeShowAlert("high", "Enter email + password");

    try {
      const cred = await createUserWithEmailAndPassword(auth, email, pass);
      await sendEmailVerification(cred.user);
      safeShowAlert("medium", "Signup done. Verify your email, then login.");
      await signOut(auth);
      showLoginUI();
    } catch (e) {
      safeShowAlert("high", e?.message || "Signup failed");
    }
  });

  // logout
  $("logoutBtn")?.addEventListener("click", async () => {
    await signOut(auth);
    chrome.storage.local.remove(["tb_user"]);
    safeShowAlert("low", "Logged out ✅");
    showLoginUI();
  });

  // main buttons
  $("scanPageBtn")?.addEventListener("click", scanPage);

  $("openDashboardBtn")?.addEventListener("click", () => {
    chrome.runtime.openOptionsPage();
  });

  $("openTechLookupBtn")?.addEventListener("click", openTechLookup);

  // cookie buttons (only works if you added these buttons in popup.html)
  $("blockCookiesBtn")?.addEventListener("click", blockCookiesForThisSite);
  $("allowCookiesBtn")?.addEventListener("click", allowCookiesForThisSite);

  // auth state
  onAuthStateChanged(auth, (user) => {
    if (user && user.emailVerified) {
      showAppUI();
      refreshSummary();
    } else {
      showLoginUI();
    }
  });
});
