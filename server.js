#!/usr/bin/env node
/**
 * CYBERSCIENZA — Bulletproof Scanner with Direct PDF Export
 */

const http = require('http');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;

// Keys are read ONLY from environment variables. No hardcoded fallback —
// on Railway, set these under your service's "Variables" tab.
const VT_API_KEY = process.env.VT_API_KEY;
const OPENROUTER_API_KEY = process.env.OPENROUTER_API_KEY;

if (!VT_API_KEY) {
  console.warn('[WARN] VT_API_KEY is not set. VirusTotal lookups will fail or return no data.');
}
if (!OPENROUTER_API_KEY) {
  console.warn('[WARN] OPENROUTER_API_KEY is not set. AI analysis will fall back to client-supplied keys only.');
}

const VT_BASE = 'https://www.virustotal.com/api/v3';
const OPENROUTER_BASE = 'https://openrouter.ai/api/v1/chat/completions';

// ---------- Front-End (Embedded HTML/CSS/JS) ----------
const HTML_PAGE = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>CYBERSCIENZA | Intelligence Portal</title>
  <link href="https://fonts.googleapis.com/css2?family=Cinzel:wght@700&family=Plus+Jakarta+Sans:wght@400;600;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-color: #030508;
      --card-bg: #0d121c;
      --accent-blue: #4f46e5;
      --accent-cyan: #06b6d4;
      --accent-silver: #e2e8f0;
      --danger: #ef4444;
      --warning: #f59e0b;
      --success: #10b981;
      --glass-border: rgba(255, 255, 255, 0.1);
    }

    * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Plus Jakarta Sans', sans-serif; }
    body { background-color: var(--bg-color); color: var(--accent-silver); min-height: 100vh; padding: 2rem 1rem; }

    .container { max-width: 900px; margin: 0 auto; }
    
    header { text-align: center; margin-bottom: 2rem; }
    header h1 { font-family: 'Cinzel', serif; font-size: 2.2rem; color: #fff; letter-spacing: 2px; }
    header p { color: var(--accent-cyan); font-size: 0.85rem; letter-spacing: 1.5px; text-transform: uppercase; margin-top: 5px; }

    .card { background: var(--card-bg); border: 1px solid var(--glass-border); border-radius: 12px; padding: 1.8rem; margin-bottom: 1.5rem; }

    .tabs { display: flex; gap: 10px; margin-bottom: 1rem; }
    .tab-btn { background: transparent; border: 1px solid var(--glass-border); color: #94a3b8; padding: 8px 16px; border-radius: 6px; cursor: pointer; font-weight: 600; }
    .tab-btn.active { background: var(--accent-cyan); color: #000; border-color: var(--accent-cyan); }

    .input-group { display: flex; gap: 10px; margin-bottom: 1rem; }
    input[type="text"], input[type="file"], input[type="password"] { flex: 1; background: #030508; border: 1px solid var(--glass-border); border-radius: 6px; padding: 0.8rem 1rem; color: #fff; outline: none; }
    button.btn-primary { background: linear-gradient(135deg, var(--accent-blue), var(--accent-cyan)); color: #fff; border: none; padding: 0 1.5rem; border-radius: 6px; font-weight: 700; cursor: pointer; }
    button.btn-primary:hover { opacity: 0.9; }

    #loadingBox { display: none; text-align: center; padding: 2rem; color: var(--accent-cyan); font-weight: 600; }
    
    #resultsCard { display: none; }
    .status-badge { display: inline-block; padding: 6px 14px; border-radius: 20px; font-size: 0.85rem; font-weight: 700; text-transform: uppercase; margin-bottom: 10px; }
    .badge-critical { background: rgba(239, 68, 68, 0.2); color: var(--danger); border: 1px solid var(--danger); }
    .badge-safe { background: rgba(16, 185, 129, 0.2); color: var(--success); border: 1px solid var(--success); }

    .pdf-download-bar { background: rgba(6, 182, 212, 0.1); border: 1px solid var(--accent-cyan); border-radius: 8px; padding: 12px 20px; display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem; }
    .btn-pdf { background: var(--success); color: #fff; border: none; padding: 0.6rem 1.2rem; font-weight: 700; border-radius: 6px; cursor: pointer; }

    .ai-box { background: rgba(79, 70, 229, 0.15); border: 1px solid var(--accent-blue); border-radius: 8px; padding: 1.2rem; margin: 1.5rem 0; line-height: 1.6; white-space: pre-wrap; font-size: 0.9rem; }

    .stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin-bottom: 1.5rem; }
    .stat-card { background: rgba(255,255,255,0.02); border: 1px solid var(--glass-border); padding: 12px; border-radius: 8px; text-align: center; }
    .stat-card .num { font-size: 1.4rem; font-weight: 700; }
    .stat-card .label { font-size: 0.7rem; color: #64748b; text-transform: uppercase; }

    .meta-table { width: 100%; border-collapse: collapse; margin-bottom: 1.5rem; font-size: 0.85rem; }
    .meta-table td { padding: 8px 12px; border: 1px solid var(--glass-border); word-break: break-all; }
    .meta-table td.key { background: rgba(255,255,255,0.03); font-weight: 600; color: #94a3b8; width: 30%; }

    .engine-list { max-height: 250px; overflow-y: auto; border: 1px solid var(--glass-border); border-radius: 8px; font-size: 0.8rem; }
    .engine-item { display: flex; justify-content: space-between; padding: 8px 12px; border-bottom: 1px solid var(--glass-border); }
    .engine-item.malicious { color: var(--danger); font-weight: bold; background: rgba(239, 68, 68, 0.05); }
  </style>
</head>
<body>

  <div class="container">
    <header>
      <h1>CYBERSCIENZA</h1>
      <p>Quantum Security Threat Intelligence Portal</p>
    </header>

    <div class="card">
      <div class="tabs">
        <button class="tab-btn active" id="tabText" onclick="setTab('text')">URL / Hash / IP</button>
        <button class="tab-btn" id="tabFile" onclick="setTab('file')">Upload File</button>
      </div>

      <div class="input-group" id="textGroup">
        <input type="text" id="targetInput" placeholder="Enter Hash, URL, or IP address...">
        <button class="btn-primary" onclick="runTextScan()">Scan Threat</button>
      </div>

      <div class="input-group" id="fileGroup" style="display:none;">
        <input type="file" id="fileInput">
        <button class="btn-primary" onclick="runFileScan()">Upload & Scan</button>
      </div>

      <div style="font-size: 0.75rem; color: #64748b; display: flex; align-items: center; gap: 8px; margin-top: 10px;">
        <label>Optional OpenRouter Key:</label>
        <input type="password" id="openrouterKey" placeholder="sk-or-v1-..." style="padding: 4px 8px; font-size: 0.75rem; max-width: 250px;">
      </div>
    </div>

    <div id="loadingBox" class="card">
      ⚡ Querying VirusTotal Security Network & Generating OpenRouter AI Analysis...
    </div>

    <div id="resultsCard" class="card">
      <div class="pdf-download-bar">
        <span>📄 Threat Intelligence Report Ready</span>
        <button class="btn-pdf" onclick="exportToPDF()">Download Threat Report (PDF)</button>
      </div>

      <div id="statusBadge" class="status-badge badge-safe">SAFE</div>
      <h2 id="reportTitle" style="margin-bottom: 5px;">Target Scan Results</h2>
      <p id="reportSub" style="color: #64748b; font-size: 0.85rem; margin-bottom: 1.5rem;"></p>

      <div class="stats-grid">
        <div class="stat-card"><div class="num" id="cntMalicious" style="color:var(--danger)">0</div><div class="label">Malicious</div></div>
        <div class="stat-card"><div class="num" id="cntSuspicious" style="color:var(--warning)">0</div><div class="label">Suspicious</div></div>
        <div class="stat-card"><div class="num" id="cntHarmless" style="color:var(--success)">0</div><div class="label">Harmless</div></div>
        <div class="stat-card"><div class="num" id="cntUndetected" style="color:#94a3b8">0</div><div class="label">Undetected</div></div>
      </div>

      <h3 style="font-size: 1rem; margin-bottom: 0.5rem; color: var(--accent-cyan);">⚡ OpenRouter AI Assessment</h3>
      <div class="ai-box" id="aiReport">Analyzing...</div>

      <h3 style="font-size: 1rem; margin-bottom: 0.5rem;">File / Target Metadata</h3>
      <table class="meta-table" id="metaTable"></table>

      <h3 style="font-size: 1rem; margin-bottom: 0.5rem;">Vendor Detections</h3>
      <div class="engine-list" id="engineList"></div>
    </div>
  </div>

  <script>
    let activeData = null;

    function setTab(type) {
      document.getElementById('tabText').classList.toggle('active', type === 'text');
      document.getElementById('tabFile').classList.toggle('active', type === 'file');
      document.getElementById('textGroup').style.display = type === 'text' ? 'flex' : 'none';
      document.getElementById('fileGroup').style.display = type === 'file' ? 'flex' : 'none';
    }

    async function runTextScan() {
      const target = document.getElementById('targetInput').value.trim();
      const openrouterKey = document.getElementById('openrouterKey').value.trim();
      if (!target) return alert('Please enter a valid target!');

      showLoading(true);
      try {
        const res = await fetch('/api/scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ target, openrouterKey })
        });
        const data = await res.json();
        showLoading(false);
        if (data.error) throw new Error(data.error);
        renderData(data);
      } catch (err) {
        showLoading(false);
        alert("Scan Error: " + err.message);
      }
    }

    async function runFileScan() {
      const fileInput = document.getElementById('fileInput');
      const openrouterKey = document.getElementById('openrouterKey').value.trim();
      if (!fileInput.files.length) return alert('Select a file to upload!');

      const formData = new FormData();
      formData.append('file', fileInput.files[0]);
      formData.append('openrouterKey', openrouterKey);

      showLoading(true);
      try {
        const res = await fetch('/api/scan', { method: 'POST', body: formData });
        const data = await res.json();
        showLoading(false);
        if (data.error) throw new Error(data.error);
        renderData(data);
      } catch (err) {
        showLoading(false);
        alert("Upload Scan Error: " + err.message);
      }
    }

    function showLoading(isLoading) {
      document.getElementById('loadingBox').style.display = isLoading ? 'block' : 'none';
      if (isLoading) document.getElementById('resultsCard').style.display = 'none';
    }

    function renderData(data) {
      activeData = data;
      document.getElementById('resultsCard').style.display = 'block';

      document.getElementById('cntMalicious').innerText = data.malicious;
      document.getElementById('cntSuspicious').innerText = data.suspicious;
      document.getElementById('cntHarmless').innerText = data.harmless;
      document.getElementById('cntUndetected').innerText = data.undetected;

      const badge = document.getElementById('statusBadge');
      if (data.malicious > 0) {
        badge.className = 'status-badge badge-critical';
        badge.innerText = \`THREAT DETECTED (\${data.malicious}/\${data.total} ENGINES)\`;
      } else {
        badge.className = 'status-badge badge-safe';
        badge.innerText = 'CLEAN / NO THREATS FOUND';
      }

      document.getElementById('reportTitle').innerText = data.target;
      document.getElementById('reportSub').innerText = \`Type: \${data.kind} | Evaluated across \${data.total} security vendors.\`;
      document.getElementById('aiReport').innerText = data.aiAnalysis || "No AI Report Generated.";

      // Render Metadata Table
      const metaTable = document.getElementById('metaTable');
      metaTable.innerHTML = '';
      Object.entries(data.meta || {}).forEach(([k, v]) => {
        metaTable.innerHTML += \`<tr><td class="key">\${k}</td><td>\${v || 'N/A'}</td></tr>\`;
      });

      // Render Engine Detections
      const engineList = document.getElementById('engineList');
      engineList.innerHTML = '';
      (data.engines || []).forEach(e => {
        const isMal = e.category === 'malicious';
        engineList.innerHTML += \`<div class="engine-item \${isMal ? 'malicious' : ''}"><span>\${e.engine}</span><span>\${e.result}</span></div>\`;
      });
    }

    function exportToPDF() {
      if (!activeData) return alert('No report data available.');
      
      const printWin = window.open('', '_blank');
      printWin.document.write(\`
        <html>
        <head>
          <title>CYBERSCIENZA Threat Report - \${activeData.target}</title>
          <style>
            body { font-family: Arial, sans-serif; padding: 30px; color: #111; }
            h1 { font-size: 24px; margin-bottom: 5px; }
            .badge { display: inline-block; padding: 4px 10px; background: #eee; font-weight: bold; margin-bottom: 20px; }
            .box { background: #f4f4f5; padding: 15px; border-radius: 6px; margin: 15px 0; white-space: pre-wrap; font-size: 14px; }
            table { width: 100%; border-collapse: collapse; margin: 15px 0; }
            td, th { border: 1px solid #ccc; padding: 8px; font-size: 12px; text-align: left; }
            th { background: #e5e7eb; }
          </style>
        </head>
        <body>
          <h1>CYBERSCIENZA THREAT REPORT</h1>
          <div class="badge">Target: \${activeData.target} (\${activeData.kind})</div>
          
          <h3>Summary Detections</h3>
          <p>Malicious: \${activeData.malicious} | Suspicious: \${activeData.suspicious} | Harmless: \${activeData.harmless} | Total Vendors: \${activeData.total}</p>

          <h3>OpenRouter AI Analysis</h3>
          <div class="box">\${activeData.aiAnalysis}</div>

          <h3>Metadata</h3>
          <table>
            \${Object.entries(activeData.meta || {}).map(([k,v]) => \`<tr><td><strong>\${k}</strong></td><td>\${v}</td></tr>\`).join('')}
          </table>

          <script>window.onload = function() { window.print(); }</s\` + \`cript>
        </body>
        </html>
      \`);
      printWin.document.close();
    }
  </script>
</body>
</html>`;

// ---------- OpenRouter API Multi-Model Engine ----------

async function generateOpenRouterAnalysis(vtSummary, clientOpenRouterKey) {
  const apiKey = clientOpenRouterKey || OPENROUTER_API_KEY;
  if (!apiKey) return "AI Summary Unavailable: Missing OpenRouter Key.";

  const prompt = `Act as a Senior Threat Analyst at CYBERSCIENZA. Provide an executive summary of this security scan:
Target: ${vtSummary.target}
Kind: ${vtSummary.kind}
Detections: ${vtSummary.malicious} Malicious / ${vtSummary.total} Vendors
MD5: ${vtSummary.meta['MD5'] || 'N/A'}
SHA256: ${vtSummary.meta['SHA-256'] || 'N/A'}

Provide 3 sections:
1. EXECUTIVE VERDICT (Is it dangerous or safe?)
2. THREAT DETAILS (Why was it flagged or clean?)
3. ACTION PLAN FOR DEFENDERS (Clear steps to take)`;

  const modelsToTry = [
    'anthropic/claude-sonnet-4.5'
  ];

  let lastError = null;

  for (const model of modelsToTry) {
    try {
      const res = await fetch(OPENROUTER_BASE, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${apiKey}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          model: model,
          messages: [{ role: 'user', content: prompt }],
          temperature: 0.3
        })
      });

      const data = await res.json().catch(() => ({}));

      if (res.ok && data.choices?.[0]?.message?.content) {
        return `[Generated using ${model}]\n\n` + data.choices[0].message.content.trim();
      }

      // Log the actual reason instead of swallowing it
      lastError = data?.error?.message || `HTTP ${res.status} ${res.statusText}`;
      console.error(`[OpenRouter] model=${model} failed: ${lastError}`, JSON.stringify(data));
    } catch (e) {
      lastError = e.message;
      console.error(`[OpenRouter] model=${model} threw:`, e);
    }
  }

  return `OpenRouter AI Service was unable to respond. Reason: ${lastError || 'unknown error'}`;
}

// ---------- VirusTotal API Engine ----------

async function vtFetch(url, opts = {}) {
  if (!VT_API_KEY) {
    throw new Error('VT_API_KEY is not configured on the server.');
  }
  const headers = Object.assign({ 'x-apikey': VT_API_KEY }, opts.headers || {});
  const res = await fetch(url, Object.assign({}, opts, { headers }));
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error((data?.error?.message) || res.statusText);
  return data;
}

function summarizeData(attrs = {}, kind, target, localHashes = {}) {
  const stats = attrs.last_analysis_stats || attrs.stats || {};
  const malicious = stats.malicious || 0;
  const suspicious = stats.suspicious || 0;
  const harmless = stats.harmless || 0;
  const undetected = stats.undetected || 0;
  const total = malicious + suspicious + harmless + undetected || 1;

  const results = attrs.last_analysis_results || attrs.results || {};
  const engines = Object.entries(results).map(([engine, details]) => ({
    engine,
    category: details.category || 'unknown',
    result: details.result || details.category || 'clean'
  }));

  const meta = {
    'Name / Label': attrs.meaningful_name || attrs.name || target,
    'Type': attrs.type_description || 'File / Asset',
    'File Size': localHashes.size ? `${localHashes.size} bytes` : (attrs.size ? `${attrs.size} bytes` : 'N/A'),
    'MD5': localHashes.md5 || attrs.md5 || 'N/A',
    'SHA-1': localHashes.sha1 || attrs.sha1 || 'N/A',
    'SHA-256': localHashes.sha256 || attrs.sha256 || 'N/A'
  };

  return { kind, target, malicious, suspicious, harmless, undetected, total, engines, meta };
}

async function handleFileScan(buffer, fileName) {
  const sha256 = crypto.createHash('sha256').update(buffer).digest('hex');
  const md5 = crypto.createHash('md5').update(buffer).digest('hex');
  const sha1 = crypto.createHash('sha1').update(buffer).digest('hex');
  const localHashes = { sha256, md5, sha1, size: buffer.length };

  try {
    const existing = await vtFetch(`${VT_BASE}/files/${sha256}`);
    if (existing?.data?.attributes) {
      return summarizeData(existing.data.attributes, 'Uploaded File', fileName, localHashes);
    }
  } catch (e) {}

  return summarizeData({}, 'Uploaded File', fileName, localHashes);
}

// ---------- HTTP Server ----------

function parseMultipart(buffer, boundary) {
  const boundaryBuffer = Buffer.from('--' + boundary);
  let start = buffer.indexOf(boundaryBuffer);
  let fileObj = null;
  let openrouterKey = '';

  while (start !== -1) {
    start += boundaryBuffer.length;
    if (buffer.subarray(start, start + 2).toString() === '--') break;

    const headerEnd = buffer.indexOf('\r\n\r\n', start);
    if (headerEnd === -1) break;

    const headers = buffer.subarray(start, headerEnd).toString('utf-8');
    const nextBoundary = buffer.indexOf(boundaryBuffer, headerEnd);
    if (nextBoundary === -1) break;

    const body = buffer.subarray(headerEnd + 4, nextBoundary - 2);

    if (headers.includes('name="file"') && headers.includes('filename=')) {
      const match = headers.match(/filename="([^"]+)"/);
      fileObj = { filename: match ? match[1] : 'file', data: body };
    } else if (headers.includes('name="openrouterKey"')) {
      openrouterKey = body.toString('utf-8').trim();
    }

    start = nextBoundary;
  }
  return { fileObj, openrouterKey };
}

const server = http.createServer((req, res) => {
  if (req.method === 'POST' && req.url === '/api/scan') {
    const chunks = [];
    req.on('data', chunk => chunks.push(chunk));
    req.on('end', async () => {
      try {
        const contentType = req.headers['content-type'] || '';
        let result;
        let openrouterKey = '';

        if (contentType.includes('multipart/form-data')) {
          const buffer = Buffer.concat(chunks);
          const boundaryMatch = contentType.match(/boundary=(?:"([^"]+)"|([^;]+))/i);
          const boundary = boundaryMatch ? (boundaryMatch[1] || boundaryMatch[2]) : null;
          const parsed = parseMultipart(buffer, boundary);

          if (!parsed.fileObj) throw new Error("No file payload detected.");
          openrouterKey = parsed.openrouterKey;
          result = await handleFileScan(parsed.fileObj.data, parsed.fileObj.filename);
        } else {
          const parsed = JSON.parse(Buffer.concat(chunks).toString('utf-8') || '{}');
          openrouterKey = parsed.openrouterKey || '';

          const target = (parsed.target || '').trim();
          if (!target) throw new Error('No target provided.');

          // Hash or URL Lookup
          try {
            const vtRes = await vtFetch(`${VT_BASE}/files/${target}`);
            result = summarizeData(vtRes.data.attributes, 'Hash / Asset', target);
          } catch (e) {
            result = summarizeData({}, 'Target Query', target);
          }
        }

        result.aiAnalysis = await generateOpenRouterAnalysis(result, openrouterKey);

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(result));
      } catch (err) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: err.message }));
      }
    });
    return;
  }

  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(HTML_PAGE);
});

server.listen(PORT, () => {
  console.log(`CYBERSCIENZA portal running at http://localhost:${PORT}`);
});
