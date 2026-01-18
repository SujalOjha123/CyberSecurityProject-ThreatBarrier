require("dotenv").config({ path: __dirname + "/.env" });

console.log("BuiltWith key loaded:", !!process.env.BUILTWITH_API_KEY);


const express = require("express");
const cors = require("cors");

const { domainLookup } = require("./builtwithService");
const { scanUrl, getAnalysis } = require("./virustotalService");

const app = express();

app.use(cors());
app.use(express.json());

// ✅ Test route (NOW app exists)
app.get("/test", (req, res) => {
  res.send("Backend is working");
});

// BuiltWith endpoint
app.post("/api/builtwith/domain", async (req, res) => {
  try {
    const { url } = req.body;
    if (!url) return res.status(400).json({ error: "url is required" });

    const data = await domainLookup(url);
    res.json(data);
  } catch (err) {
    if (err.message && err.message.includes("API Credits")) {
      return res.status(402).json({
        error: "BUILTWITH_CREDITS_EXHAUSTED",
        message: "BuiltWith API credits are exhausted"
      });
    }
    res.status(500).json({ error: err.message });
  }
});
// ---------------- VirusTotal: URL Scan ----------------

// Submit URL for scan (returns analysis id)
app.post("/api/virustotal/url/scan", async (req, res) => {
  try {
    const { url } = req.body;
    if (!url) return res.status(400).json({ error: "url is required" });

    const data = await scanUrl(url);
    res.json(data);
  } catch (err) {
    res.status(500).json({
      error: "VIRUSTOTAL_SCAN_FAILED",
      message: err.message
    });
  }
});

// Fetch analysis result by ID
app.get("/api/virustotal/analysis/:id", async (req, res) => {
  try {
    const data = await getAnalysis(req.params.id);
    res.json(data);
  } catch (err) {
    res.status(500).json({
      error: "VIRUSTOTAL_ANALYSIS_FAILED",
      message: err.message
    });
  }
});


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`API server running on port ${PORT}`));
