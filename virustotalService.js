const VT_BASE = "https://www.virustotal.com/api/v3";

// helper to build headers
function vtHeaders() {
  const key = process.env.VIRUSTOTAL_API_KEY;
  if (!key) {
    throw new Error("VIRUSTOTAL_API_KEY not set in .env");
  }
  return {
    "x-apikey": key,
    "accept": "application/json"
  };
}

/**
 * Submit a URL to VirusTotal for scanning
 * VirusTotal returns an analysis ID
 */
async function scanUrl(url) {
  const body = new URLSearchParams();
  body.append("url", url);

  const res = await fetch(`${VT_BASE}/urls`, {
    method: "POST",
    headers: {
      ...vtHeaders(),
      "content-type": "application/x-www-form-urlencoded"
    },
    body
  });

  const data = await res.json();
  if (!res.ok) {
    throw new Error(data?.error?.message || "VirusTotal URL scan failed");
  }

  return data; // contains data.id (analysis id)
}

/**
 * Get analysis result by ID
 */
async function getAnalysis(analysisId) {
  const res = await fetch(`${VT_BASE}/analyses/${analysisId}`, {
    headers: vtHeaders()
  });

  const data = await res.json();
  if (!res.ok) {
    throw new Error(data?.error?.message || "VirusTotal analysis fetch failed");
  }

  return data;
}

module.exports = {
  scanUrl,
  getAnalysis
};
