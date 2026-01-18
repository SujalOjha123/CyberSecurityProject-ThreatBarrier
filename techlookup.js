/* ThreatBarrier — Technology Lookup (FREE local scan)
   - No external API (local scan always works)
   - Optional BuiltWith lookup via your Node backend (graceful if credits exhausted)
   - Executes detector inside a real website tab (http/https)
   - Renders results + export CSV
*/

const $ = (id) => document.getElementById(id);

let lastDetected = [];
let lastUrl = "";

function setStatus(msg) {
  const el = $("status");
  if (el) el.textContent = msg || "";
}

function safeText(x) {
  return x === null || x === undefined ? "" : String(x);
}

function escapeHtml(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#039;"
  }[c]));
}

function makeRow(k, v, isLink = false) {
  const vv = safeText(v) || "N/A";
  const vHtml = isLink && vv !== "N/A"
    ? `<a class="link" href="${escapeHtml(vv)}" target="_blank" rel="noreferrer">${escapeHtml(vv)}</a>`
    : escapeHtml(vv);

  return `<div class="kv-row"><div class="k">${escapeHtml(k)}</div><div class="v">${vHtml}</div></div>`;
}

function guessCompanyFromHost(hostname = "") {
  if (!hostname) return "";
  const parts = hostname.split(".").filter(Boolean);
  if (parts.length >= 2) return parts[parts.length - 2].toUpperCase();
  return hostname.toUpperCase();
}

/* ---------------- BuiltWith backend lookup (optional) ---------------- */
async function lookupTechnology(domain) {
  const res = await fetch("http://localhost:3000/api/builtwith/domain", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url: domain })
  });
  return await res.json();
}

/* ---------------- detector runs inside visited site tab ---------------- */
function detectorInPage() {
  const url = location.href;

  const scripts = Array.from(document.scripts || [])
    .map((s) => s.src || "")
    .filter(Boolean);

  const html = (document.documentElement?.outerHTML || "").toLowerCase();
  const generator =
    (document.querySelector('meta[name="generator"]')?.getAttribute("content") || "");

  const title = document.title || "";
  const description =
    document.querySelector('meta[name="description"]')?.getAttribute("content") ||
    document.querySelector('meta[property="og:description"]')?.getAttribute("content") ||
    "";

  const siteName = document.querySelector('meta[property="og:site_name"]')?.getAttribute("content") || "";
  const ogUrl = document.querySelector('meta[property="og:url"]')?.getAttribute("content") || "";
  const lang = document.documentElement?.getAttribute("lang") || "";

  const hostname = location.hostname;
  const protocol = location.protocol;

  const cookies = document.cookie || "";

  const globals = {
    react: !!window.__REACT_DEVTOOLS_GLOBAL_HOOK__ || !!document.querySelector('[data-reactroot], [data-reactid]'),
    nextjs: !!window.__NEXT_DATA__ || html.includes("/_next/"),
    vue: !!window.Vue || !!document.querySelector("[data-v-app]") || html.includes("vue"),
    nuxt: !!window.__NUXT__ || html.includes("/_nuxt/"),
    angular: !!window.ng || !!document.querySelector("[ng-version]"),
    svelte: html.includes("svelte") || scripts.some((s) => s.includes("svelte")),
    jquery: !!window.jQuery || scripts.some((s) => s.includes("jquery")),

    shopify: !!window.Shopify || html.includes("cdn.shopify.com") || html.includes("shopify"),
    wp: generator.toLowerCase().includes("wordpress") || html.includes("wp-content") || html.includes("wp-includes"),
    woocommerce: html.includes("woocommerce") || html.includes("wc-") || cookies.includes("woocommerce_"),
    magento: html.includes("mage/") || html.includes("magento") || cookies.includes("frontend="),
    wix: html.includes("wix.com") || html.includes("wixsite") || scripts.some((s) => s.includes("wix")),
    webflow: html.includes("webflow") || scripts.some((s) => s.includes("webflow")),

    gtm: html.includes("googletagmanager.com/gtm.js") || scripts.some((s) => s.includes("googletagmanager.com/gtm.js")),
    ga: html.includes("google-analytics.com") || html.includes("gtag(") || scripts.some((s) => s.includes("google-analytics.com")),
    fbPixel: html.includes("connect.facebook.net/en_US/fbevents.js") || html.includes("fbq("),
    hotjar: html.includes("static.hotjar.com") || html.includes("hj("),

    stripe: html.includes("js.stripe.com") || scripts.some((s) => s.includes("js.stripe.com")),
    cloudflareHint: html.includes("cdnjs.cloudflare.com") || html.includes("cloudflare") || scripts.some((s) => s.includes("cdnjs.cloudflare.com")),
  };

  const tech = [];
  const add = (name, category, version = "") => tech.push({ name, category, version });

  // CMS / builders
  if (globals.wp) add("WordPress", "CMS");
  if (globals.webflow) add("Webflow", "Site Builder");
  if (globals.wix) add("Wix", "Site Builder");

  // Ecommerce
  if (globals.shopify) add("Shopify", "Ecommerce");
  if (globals.woocommerce) add("WooCommerce", "Ecommerce");
  if (globals.magento) add("Magento", "Ecommerce");

  // Frameworks
  if (globals.react) add("React", "Frontend Framework");
  if (globals.nextjs) add("Next.js", "Frontend Framework");
  if (globals.vue) add("Vue.js", "Frontend Framework");
  if (globals.nuxt) add("Nuxt", "Frontend Framework");
  if (globals.angular) add("Angular", "Frontend Framework");
  if (globals.svelte) add("Svelte", "Frontend Framework");
  if (globals.jquery) add("jQuery", "JavaScript Library");

  // Analytics
  if (globals.gtm) add("Google Tag Manager", "Tag Manager");
  if (globals.ga) add("Google Analytics", "Analytics");
  if (globals.fbPixel) add("Meta Pixel (Facebook)", "Analytics");
  if (globals.hotjar) add("Hotjar", "Analytics");

  // Payments
  if (globals.stripe) add("Stripe", "Payments");

  // CDN hint
  if (globals.cloudflareHint) add("Cloudflare (hint)", "CDN / Hosting");

  if (generator && !globals.wp && generator.toLowerCase().includes("wordpress")) {
    add("WordPress", "CMS");
  }

  // de-dupe
  const seen = new Set();
  const technologies = tech.filter((t) => {
    const k = `${t.name}||${t.category}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });

  return {
    url,
    technologies,
    meta: { title, description, generator, siteName, ogUrl, lang },
    net: { hostname, protocol },
  };
}

/* ---------------- get a real website tab (NOT chrome-extension://) ---------------- */
async function getBestWebTab() {
  const tabs = await chrome.tabs.query({ currentWindow: true });

  // active website tab
  const activeWeb = tabs.find(t =>
    t.active && t.url && (t.url.startsWith("http://") || t.url.startsWith("https://"))
  );
  if (activeWeb) return activeWeb;

  // fallback: any website tab
  const anyWeb = tabs.find(t =>
    t.url && (t.url.startsWith("http://") || t.url.startsWith("https://"))
  );
  return anyWeb || null;
}

/* ---------------- run lookup ---------------- */
async function runLookup() {
  const tab = await getBestWebTab();

  if (!tab || !tab.id) {
    setStatus("Open any website (http/https) in a tab, then click Lookup.");
    return;
  }

  setStatus("Scanning…");

  try {
    const injected = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: detectorInPage,
    });

    const result = injected?.[0]?.result;
    if (!result) {
      setStatus("No result returned.");
      return;
    }

    lastUrl = result.url || tab.url || "";
    lastDetected = result.technologies || [];

    renderAll(result);
    $("btnExport").disabled = lastDetected.length === 0;

    // -------- BuiltWith lookup (optional / external) --------
    try {
      const domain = new URL(lastUrl).hostname;
      const data = await lookupTechnology(domain);

      if (data?.error === "BUILTWITH_CREDITS_EXHAUSTED") {
        setStatus(
          `Done. Found ${lastDetected.length} technologies. BuiltWith unavailable (API credits exhausted).`
        );
        return;
      }

      console.log("BuiltWith result:", data);
      // Optional: later display BuiltWith results separately
    } catch (e) {
      console.warn("BuiltWith lookup failed:", e.message);
    }

    setStatus(`Done. Found ${lastDetected.length} technologies.`);
  } catch (err) {
    console.error("TechLookup error:", err);
    setStatus("Scan failed. Check manifest permissions: scripting + host_permissions.");
  }
}

/* ---------------- render UI ---------------- */
function renderCards(techList) {
  const el = $("techCards");
  if (!el) return;

  if (!techList?.length) {
    el.innerHTML = `<div class="card note">No technologies detected on this page.</div>`;
    return;
  }

  el.innerHTML = techList.map((t) => `
    <div class="tech">
      <div class="tech-top">
        <div>
          <div class="tech-name">${escapeHtml(t.name)}</div>
          <div class="tech-ver">${escapeHtml(t.version ? `Version: ${t.version}` : "Version: N/A")}</div>
        </div>
      </div>
      <div class="pill">${escapeHtml(t.category || "Category")}</div>
    </div>
  `).join("");
}

function renderSide(result) {
  const meta = result.meta || {};
  const net = result.net || {};

  const companyName = meta.siteName || guessCompanyFromHost(net.hostname) || "N/A";
  const homepage = result.url || "N/A";

  $("companyBox").innerHTML = [
    makeRow("Website", homepage, true),
    makeRow("Host", net.hostname || "N/A"),
    makeRow("Company", companyName),
    makeRow("Generator", meta.generator || "N/A"),
  ].join("");

  $("metaBox").innerHTML = [
    makeRow("Title", meta.title || "N/A"),
    makeRow("Description", meta.description || "N/A"),
    makeRow("Language", meta.lang || "N/A"),
    makeRow("OG URL", meta.ogUrl || "N/A", true),
  ].join("");

  $("netBox").innerHTML = [
    makeRow("Protocol", net.protocol || "N/A"),
    makeRow("Hostname", net.hostname || "N/A"),
    makeRow("IP / TLS", "Not available (browser-only)"),
  ].join("");
}

function renderAll(result) {
  if ($("urlInput")) $("urlInput").value = result.url || "";
  renderCards(result.technologies || []);
  renderSide(result);
}

/* ---------------- export CSV ---------------- */
function exportCSV() {
  if (!lastDetected?.length) return;

  const rows = [
    ["url", "name", "category", "version"],
    ...lastDetected.map((t) => [
      lastUrl,
      t.name || "",
      t.category || "",
      t.version || ""
    ])
  ];

  const csv = rows
    .map((r) => r.map((cell) => `"${String(cell).replace(/"/g, '""')}"`).join(","))
    .join("\n");

  const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);

  const a = document.createElement("a");
  a.href = url;
  a.download = "threatbarrier-techlookup.csv";
  a.click();
  URL.revokeObjectURL(url);
}

/* ---------------- init ---------------- */
document.addEventListener("DOMContentLoaded", async () => {
  // show active website tab URL (if exists)
  const tab = await getBestWebTab();
  if (tab?.url && $("urlInput")) $("urlInput").value = tab.url;

  $("btnLookup")?.addEventListener("click", runLookup);
  $("btnRefresh")?.addEventListener("click", runLookup);
  $("btnExport")?.addEventListener("click", exportCSV);

  // optional: auto run on open
  if (tab?.url) runLookup();
});
