const API = "http://localhost:3000";
const $ = (id) => document.getElementById(id);

let currentVT = null;
let currentFilter = "all";
let rawVisible = false;

async function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function catClass(cat) {
  if (cat === "malicious") return "bad";
  if (cat === "suspicious") return "warn";
  if (cat === "harmless") return "good";
  return "neutral";
}

function safe(v) {
  return v === null || v === undefined ? "" : String(v);
}

function renderSummary(stats) {
  const malicious = stats?.malicious ?? 0;
  const suspicious = stats?.suspicious ?? 0;
  const harmless = stats?.harmless ?? 0;
  const undetected = stats?.undetected ?? 0;

  $("summary").innerHTML = `
    <div class="badge bad"><span class="num">${malicious}</span> Malicious</div>
    <div class="badge warn"><span class="num">${suspicious}</span> Suspicious</div>
    <div class="badge good"><span class="num">${harmless}</span> Clean</div>
    <div class="badge neutral"><span class="num">${undetected}</span> Undetected</div>
  `;
}

function getVendorRows(vtJson) {
  // VirusTotal "url_analysis" response: data.attributes.results is a vendor map
  const results = vtJson?.data?.attributes?.results || {};

  const rows = Object.entries(results).map(([vendor, r]) => ({
    vendor,
    category: r?.category || "unknown",
    result: r?.result || ""
  }));

  // sort malicious -> suspicious -> harmless -> others
  const order = { malicious: 0, suspicious: 1, harmless: 2, undetected: 3, unknown: 9 };
  rows.sort(
    (a, b) => (order[a.category] ?? 9) - (order[b.category] ?? 9) || a.vendor.localeCompare(b.vendor)
  );

  return rows;
}

function renderVendorTable(vtJson) {
  const tbody = $("vendorRows");

  const rows = getVendorRows(vtJson).filter((r) =>
    currentFilter === "all" ? true : r.category === currentFilter
  );

  tbody.innerHTML =
    rows
      .map(
        (r) => `
      <tr>
        <td>${safe(r.vendor)}</td>
        <td><span class="tag ${catClass(r.category)}">${safe(r.category)}</span></td>
        <td>${safe(r.result)}</td>
      </tr>
    `
      )
      .join("") || `<tr><td colspan="3">No results for this filter.</td></tr>`;
}

function renderVT(vtJson) {
  currentVT = vtJson;

  // link (optional)
  const selfLink = vtJson?.data?.links?.self;
  const linkEl = $("vtLink");
  if (selfLink) {
    linkEl.href = selfLink;
    linkEl.style.display = "";
  } else {
    linkEl.style.display = "none";
  }

  const stats = vtJson?.data?.attributes?.stats || {};
  renderSummary(stats);
  renderVendorTable(vtJson);

  const raw = $("rawJson");
  raw.textContent = JSON.stringify(vtJson, null, 2);
  raw.classList.toggle("hidden", !rawVisible);
}

async function scanUrl(url) {
  // 1) submit URL
  const submit = await fetch(`${API}/api/virustotal/url/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url })
  }).then((r) => r.json());

  if (submit.error) throw new Error(submit.message || submit.error);

  const id = submit?.data?.id;
  if (!id) throw new Error("No analysis id returned from backend.");

  // 2) poll analysis
  for (let i = 0; i < 12; i++) {
    await sleep(2000);

    const result = await fetch(`${API}/api/virustotal/analysis/${encodeURIComponent(id)}`).then((r) =>
      r.json()
    );

    if (result.error) throw new Error(result.message || result.error);

    const status = result?.data?.attributes?.status;
    if (status === "completed") return result;
  }

  throw new Error("Timed out waiting for analysis.");
}

// Scan button
$("btnScan").addEventListener("click", async () => {
  const url = $("url").value.trim();
  if (!url) {
    $("status").textContent = "Enter a URL first.";
    return;
  }

  $("btnScan").disabled = true;
  $("status").textContent = "Submitting to VirusTotal…";

  try {
    const result = await scanUrl(url);
    const stats = result?.data?.attributes?.stats;

    $("status").textContent = `Done. Malicious: ${stats?.malicious ?? 0}, Suspicious: ${
      stats?.suspicious ?? 0
    }, Harmless: ${stats?.harmless ?? 0}`;

    renderVT(result);
  } catch (e) {
    $("status").textContent = "Error: " + e.message;
    $("summary").innerHTML = "";
    $("vendorRows").innerHTML = "";
    $("rawJson").textContent = "";
  } finally {
    $("btnScan").disabled = false;
  }
});

// filter chips
document.querySelectorAll(".chip").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".chip").forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    currentFilter = btn.dataset.filter;
    if (currentVT) renderVendorTable(currentVT);
  });
});

// raw toggle
$("btnToggleRaw").addEventListener("click", () => {
  rawVisible = !rawVisible;
  $("btnToggleRaw").textContent = rawVisible ? "Hide raw" : "Show raw";
  if (currentVT) renderVT(currentVT);
});

// initial UI
$("status").textContent = "Idle";
$("summary").innerHTML = "";
$("vendorRows").innerHTML = `<tr><td colspan="3">No data yet. Scan a URL to see vendor analysis.</td></tr>`;
