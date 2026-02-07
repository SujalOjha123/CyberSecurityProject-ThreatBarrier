# CyberSecurityProject-ThreatBarrier
Browser extension for real-time request monitoring, threat scoring, and privacy protection.

ThreatBarrier is a browser-based security, privacy, and threat‑intelligence system built using Chrome Manifest V3. It works like a browser firewall, helping users monitor, analyze, and control hidden web activities such as trackers, malicious requests, phishing URLs, risky cookies, and exposed technologies in real time.

This project is developed as a Final Year Project (FYP) with a focus on practical browser security, transparency, and user awareness.

**🚀 Key Features
🔍 Live Network Request Monitoring**

Monitors outgoing browser requests using chrome.declarativeNetRequest

Identifies request origin (first‑party / third‑party)

Logs request details in real time

Displays network activity in the dashboard

🛑 Browser‑Level Blocking (Firewall Rules)

Uses Declarative Net Request (DNR) engine

Blocks malicious or user‑defined domains instantly

Dynamic rule updates without reloading the extension

🧠 Threat Intelligence & Risk Analysis

Phishing detection using OpenPhish public feed

Optional integration with:

VirusTotal (URL & file analysis)

URLhaus (malware URLs)

Generates risk scores (Low / Medium / High) based on reputation and behavior

🍪 Cookie Inspector & Privacy Control

Fetches site cookies using chrome.cookies

Analyzes cookies based on:

Secure / HttpOnly flags

Expiry duration

First‑party vs third‑party

Classifies cookies by risk level

Allows users to block or allow cookies using rules

🌐 Technology & Infrastructure Lookup

Detects website technologies via backend processing

Identifies:

Web server (Apache, Nginx, etc.)

CMS / frameworks

Hosting & protocol information

Helps understand potential attack surface of a website

🔐 DNS & TLS Security Analysis

Performs DNS resolution checks

Verifies HTTPS and TLS availability

Checks certificate presence and security indicators

📊 Interactive Dashboard

Real‑time visualization of:

Network requests

Threat scores

Detected Trackers

Custom Rules 

Cookie risk levels

CSV export of network logs

Popup UI for quick security insights

🧩 Project Architecture

ThreatBarrier follows a Client–Extension–Backend architecture, separating browser‑level monitoring from advanced threat analysis.

User Browser
   ↓
Chrome Extension (Manifest V3)
   ↓
Node.js / Express Backend
   ↓
Threat Intelligence Services
🔹 Chrome Extension Layer

Responsible for real‑time browser interaction:

manifest.json

Defines permissions (DNR, cookies, host access)

serviceworker.js

Network request monitoring

Cookie fetching and classification

Rule creation and enforcement

Sends URLs and metadata to backend

dashboard.js / popup.js

Displays logs, risks, and scores

🔹 Backend Layer (Node.js / Express)

Handles secure and advanced analysis that cannot be performed inside a Chrome extension:

Technology detection & lookup

DNS and TLS security analysis

VirusTotal URL & file scanning

URLhaus malware verification

OpenPhish phishing validation

Threat scoring engine

The backend protects API keys, avoids CORS limitations, and performs heavy analysis securely.

🔹 Threat Intelligence Sources

OpenPhish (public feed)

VirusTotal API

URLhaus

🛠️ Technologies Used

Chrome Extension (Manifest V3)

JavaScript (ES6+)

Chrome APIs:

declarativeNetRequest

cookies

storage

Node.js & Express.js

OpenPhish Public Feed

VirusTotal API (optional)

⚙️ Installation

Clone the repository

git clone https://github.com/SujalOjha123/CyberSecurityProject-ThreatBarrier.git

Open Chrome and go to:

chrome://extensions

Enable Developer Mode

Click Load Unpacked

Select the extension/ folder

Backend (Optional but Recommended)
cd backend
npm install
node server.js
🎯 Project Objectives

Make hidden browser activity visible

Help users understand privacy and security risks

Provide user‑controlled blocking instead of silent filtering

Demonstrate real‑world browser security concepts

📚 Academic & Educational Value

This project demonstrates:

Practical use of Chrome Manifest V3

Browser‑level firewall concepts

Threat‑intelligence integration

Secure backend design

Full‑stack development (Extension + Server)
