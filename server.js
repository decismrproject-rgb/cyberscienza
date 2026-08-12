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
    input[type="text"], input[type="file"] { flex: 1; background: #030508; border: 1px solid var(--glass-border); border-radius: 6px; padding: 0.8rem 1rem; color: #fff; outline: none; }
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
    </div>

    <div id="loadingBox" class="card">
      ⚡ Querying VirusTotal Security Network & Generating AI Analysis...
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

      <h3 style="font-size: 1rem; margin-bottom: 0.5rem; color: var(--accent-cyan);">⚡ AI Threat Assessment</h3>
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
      if (!target) return alert('Please enter a valid target!');

      showLoading(true);
      try {
        const res = await fetch('/api/scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ target })
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
      if (!fileInput.files.length) return alert('Select a file to upload!');

      const formData = new FormData();
      formData.append('file', fileInput.files[0]);

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

    // Lightweight Markdown → HTML renderer for the AI narrative block
    function mdToHtml(md) {
      const lines = md.replace(/\\r\\n/g, '\\n').split('\\n');
      let html = '';
      let inList = false;

      const inline = (t) => t
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/\\*\\*(.+?)\\*\\*/g, '<strong>$1</strong>')
        .replace(/\\*(.+?)\\*/g, '<em>$1</em>')
        .replace(/\`(.+?)\`/g, '<code>$1</code>');

      const closeList = () => { if (inList) { html += '</ul>'; inList = false; } };

      for (let raw of lines) {
        const line = raw.trim();
        if (!line) { closeList(); continue; }
        if (/^-{3,}$/.test(line)) { closeList(); html += '<hr class="md-rule"/>'; continue; }
        let m;
        if ((m = line.match(/^###\\s+(.*)/))) { closeList(); html += \`<h4 class="md-h3">\${inline(m[1])}</h4>\`; continue; }
        if ((m = line.match(/^##\\s+(.*)/))) { closeList(); html += \`<h3 class="md-h2">\${inline(m[1])}</h3>\`; continue; }
        if ((m = line.match(/^#\\s+(.*)/))) { closeList(); html += \`<h2 class="md-h1">\${inline(m[1])}</h2>\`; continue; }
        if ((m = line.match(/^[-*]\\s+(.*)/))) {
          if (!inList) { html += '<ul class="md-list">'; inList = true; }
          html += \`<li>\${inline(m[1])}</li>\`;
          continue;
        }
        closeList();
        html += \`<p class="md-p">\${inline(line)}</p>\`;
      }
      closeList();
      return html;
    }

    function exportToPDF() {
      if (!activeData) return alert('No report data available.');

      const printWin = window.open('', '_blank');
      const isThreat = activeData.malicious > 0;
      const statusLabel = isThreat ? \`THREAT DETECTED — \${activeData.malicious} OF \${activeData.total} ENGINES\` : 'CLEAN — NO THREATS DETECTED';
      const statusColor = isThreat ? '#b91c1c' : '#0f766e';
      const statusBg = isThreat ? '#fef2f2' : '#f0fdfa';
      const detectionRate = Math.round((activeData.malicious / activeData.total) * 100);
      const reportId = (activeData.meta && (activeData.meta['SHA-256'] || activeData.meta['MD5'])) ?
        (activeData.meta['SHA-256'] || activeData.meta['MD5']).slice(0, 16).toUpperCase() :
        Math.random().toString(36).slice(2, 10).toUpperCase();
      const generatedAt = new Date();
      const generatedAtStr = generatedAt.toLocaleString('en-US', { dateStyle: 'long', timeStyle: 'short' });

      const metaRows = Object.entries(activeData.meta || {})
        .map(([k, v]) => \`<tr><td class="key">\${k}</td><td class="val">\${v || '—'}</td></tr>\`)
        .join('');

      const engineRows = (activeData.engines || [])
        .slice()
        .sort((a, b) => (a.category === 'malicious' ? -1 : 1) - (b.category === 'malicious' ? -1 : 1))
        .map(e => {
          const mal = e.category === 'malicious';
          return \`<tr class="\${mal ? 'mal-row' : ''}"><td>\${e.engine}</td><td>\${mal ? '● Malicious' : '○ ' + (e.result || 'Clean')}</td></tr>\`;
        })
        .join('') || '<tr><td colspan="2" style="text-align:center;color:#94a3b8;">No vendor data available</td></tr>';

      const aiRawText = (activeData.aiAnalysis || 'No AI report generated.')
        .replace(/^\\[Generated using[^\\]]*\\]\\s*/i, '')
        .trim();
      const aiSections = mdToHtml(aiRawText);

      printWin.document.write(\`
        <html>
        <head>
          <title>Cyberscienza Threat Intelligence Report — \${activeData.target}</title>
          <meta charset="UTF-8"/>
          <link href="https://fonts.googleapis.com/css2?family=Cinzel:wght@600;700&family=Source+Serif+4:ital,wght@0,400;0,600;1,400&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
          <style>
            @page { size: A4; margin: 0; }
            * { box-sizing: border-box; }
            body {
              font-family: 'Inter', -apple-system, Segoe UI, Arial, sans-serif;
              padding: 0;
              margin: 0;
              color: #1e2430;
              font-size: 13px;
              -webkit-print-color-adjust: exact;
              print-color-adjust: exact;
              background-color: #f3f5fb;
              background-image:
                radial-gradient(circle at 92% 4%, rgba(79,70,229,0.10), transparent 40%),
                radial-gradient(circle at 4% 30%, rgba(6,182,212,0.10), transparent 38%),
                radial-gradient(circle at 96% 70%, rgba(16,185,129,0.08), transparent 36%),
                radial-gradient(circle at 8% 92%, rgba(245,158,11,0.08), transparent 34%),
                linear-gradient(180deg, #f3f5fb 0%, #eef1f9 100%);
              background-attachment: fixed;
            }

            /* Decorative geometric shapes scattered on the page */
            .shape { position: fixed; z-index: 0; pointer-events: none; }
            .shape-ring {
              width: 130px; height: 130px; border-radius: 50%;
              border: 14px solid rgba(79,70,229,0.08);
              top: 250px; right: -40px;
            }
            .shape-ring-sm {
              width: 70px; height: 70px; border-radius: 50%;
              border: 10px solid rgba(6,182,212,0.10);
              top: 620px; left: -25px;
            }
            .shape-square {
              width: 90px; height: 90px; border-radius: 18px;
              background: rgba(16,185,129,0.06);
              transform: rotate(18deg);
              bottom: 160px; right: 20px;
            }
            .shape-tri {
              width: 0; height: 0; bottom: 40px; left: 20px;
              border-left: 45px solid transparent;
              border-right: 45px solid transparent;
              border-bottom: 78px solid rgba(245,158,11,0.07);
            }
            .shape-dots {
              top: 470px; right: 30px; width: 90px; height: 46px;
              background-image: radial-gradient(rgba(79,70,229,0.22) 1.6px, transparent 1.6px);
              background-size: 11px 11px;
            }

            /* Cover strip */
            .cover {
              background: #0b1120;
              background-image:
                radial-gradient(circle at 88% -10%, rgba(6,182,212,0.35), transparent 45%),
                radial-gradient(circle at 8% 115%, rgba(79,70,229,0.35), transparent 45%),
                linear-gradient(135deg, #0b1120 0%, #131c31 55%, #0e1c2b 100%);
              color: #fff;
              padding: 44px 48px 40px 48px;
              position: relative;
              overflow: hidden;
              z-index: 1;
            }
            .cover::after {
              content: "";
              position: absolute;
              top: -60px; right: -60px;
              width: 220px; height: 220px;
              border-radius: 50%;
              background: radial-gradient(circle, rgba(6,182,212,0.28), transparent 70%);
            }
            .cover::before {
              content: "";
              position: absolute;
              bottom: -80px; left: 60px;
              width: 200px; height: 200px;
              border-radius: 50%;
              background: radial-gradient(circle, rgba(79,70,229,0.30), transparent 70%);
            }
            .cover-hex {
              position: absolute; top: 18px; right: 220px;
              width: 46px; height: 46px;
              border: 2px solid rgba(255,255,255,0.12);
              transform: rotate(45deg);
              border-radius: 10px;
            }
            .cover-bar {
              position: absolute; left: 0; bottom: 0; width: 100%; height: 6px;
              background: linear-gradient(90deg, #4f46e5, #06b6d4, #10b981, #f59e0b);
            }
            .cover-top {
              display: flex;
              justify-content: space-between;
              align-items: flex-start;
              margin-bottom: 26px;
              position: relative;
              z-index: 1;
            }
            .brandmark { display: flex; align-items: center; gap: 10px; }
            .brandmark .mark {
              width: 34px; height: 34px;
              border-radius: 8px;
              background: linear-gradient(135deg, #4f46e5, #06b6d4);
              display: flex; align-items: center; justify-content: center;
              font-family: 'Cinzel', serif; font-weight: 700; color: #fff; font-size: 15px;
              box-shadow: 0 4px 14px rgba(6,182,212,0.35);
            }
            .brandmark .name { font-family: 'Cinzel', serif; font-weight: 700; letter-spacing: 2px; font-size: 15px; }
            .brandmark .tagline { font-size: 9px; letter-spacing: 1.5px; color: #7dd3fc; text-transform: uppercase; margin-top: 1px; }
            .report-id { text-align: right; font-size: 10px; color: #94a3b8; line-height: 1.6; }
            .report-id b { color: #e2e8f0; font-weight: 600; }

            .cover-title { font-family: 'Cinzel', serif; font-size: 25px; font-weight: 600; letter-spacing: 0.5px; margin-bottom: 6px; position: relative; z-index: 1; }
            .cover-target { font-family: 'Source Serif 4', serif; font-size: 13px; color: #cbd5e1; word-break: break-all; position: relative; z-index: 1; }
            .cover-target .type-chip {
              display: inline-block; margin-left: 8px; padding: 2px 9px; border-radius: 999px;
              background: rgba(255,255,255,0.12); font-family: 'Inter', sans-serif; font-size: 9px;
              letter-spacing: 0.5px; text-transform: uppercase; color: #a5f3fc;
              border: 1px solid rgba(165,243,252,0.3);
            }

            .verdict-strip {
              margin-top: 26px;
              display: flex; align-items: center; gap: 18px;
              position: relative; z-index: 1;
            }
            .verdict-pill {
              display: inline-flex; align-items: center; gap: 8px;
              padding: 9px 20px; border-radius: 999px; font-weight: 700; font-size: 12px;
              letter-spacing: 0.5px; color: \${statusColor}; background: \${statusBg};
              border: 1px solid \${statusColor};
              box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            }
            .verdict-rate { font-size: 10px; color: #94a3b8; }
            .verdict-rate b { color: #fff; font-size: 13px; }

            .content { padding: 32px 48px 40px 48px; position: relative; z-index: 1; }

            .stats-grid {
              display: grid;
              grid-template-columns: repeat(4, 1fr);
              gap: 12px;
              margin-bottom: 30px;
            }
            .stat-card {
              border-radius: 12px;
              padding: 16px 10px 14px 10px;
              text-align: center;
              border: 1px solid #e6e9ef;
              background: #ffffff;
              box-shadow: 0 2px 8px rgba(15,23,42,0.05);
              position: relative;
              overflow: hidden;
            }
            .stat-card::before {
              content: "";
              position: absolute; top: 0; left: 0; right: 0; height: 4px;
            }
            .stat-mal::before { background: linear-gradient(90deg, #f87171, #dc2626); }
            .stat-sus::before { background: linear-gradient(90deg, #fbbf24, #d97706); }
            .stat-harm::before { background: linear-gradient(90deg, #34d399, #0d9488); }
            .stat-undet::before { background: linear-gradient(90deg, #94a3b8, #64748b); }
            .stat-card .num { font-size: 25px; font-weight: 700; font-family: 'Source Serif 4', serif; margin-top: 4px; }
            .stat-card .label { font-size: 9px; text-transform: uppercase; letter-spacing: 0.8px; color: #6b7688; margin-top: 3px; font-weight: 600; }
            .stat-mal .num { color: #dc2626; }
            .stat-sus .num { color: #d97706; }
            .stat-harm .num { color: #0d9488; }
            .stat-undet .num { color: #64748b; }

            .section-head {
              display: flex; align-items: center; gap: 10px;
              margin: 30px 0 14px 0;
            }
            .section-head .idx {
              width: 24px; height: 24px; border-radius: 7px; color: #fff; font-size: 11px; font-weight: 700;
              display: flex; align-items: center; justify-content: center; flex-shrink: 0;
              box-shadow: 0 3px 8px rgba(15,23,42,0.18);
            }
            .section-head.s1 .idx { background: linear-gradient(135deg, #4f46e5, #6366f1); }
            .section-head.s2 .idx { background: linear-gradient(135deg, #06b6d4, #0891b2); }
            .section-head.s3 .idx { background: linear-gradient(135deg, #f59e0b, #d97706); }
            .section-head h3 {
              font-size: 12px;
              text-transform: uppercase;
              letter-spacing: 1.2px;
              color: #0b1120;
              font-weight: 700;
            }
            .section-head .line { flex: 1; height: 2px; border-radius: 2px; background: linear-gradient(90deg, #e6e9ef, transparent); }

            .ai-box {
              background: #ffffff;
              border: 1px solid #e6e9ef;
              border-left: 4px solid #4f46e5;
              border-radius: 10px;
              padding: 20px 22px;
              font-family: 'Source Serif 4', serif;
              font-size: 12.5px;
              line-height: 1.75;
              color: #232a38;
              box-shadow: 0 3px 12px rgba(15,23,42,0.05);
            }
            .ai-box .md-h1 { font-family: 'Cinzel', serif; font-size: 15px; color: #0b1120; margin: 0 0 10px 0; }
            .ai-box .md-h2 { font-family: 'Inter', sans-serif; font-size: 12px; text-transform: uppercase; letter-spacing: 0.8px; color: #4f46e5; margin: 16px 0 8px 0; padding-bottom: 4px; border-bottom: 2px solid #e6e9ef; }
            .ai-box .md-h3 { font-family: 'Inter', sans-serif; font-size: 11.5px; font-weight: 700; color: #0891b2; margin: 12px 0 6px 0; }
            .ai-box .md-p { margin: 0 0 9px 0; }
            .ai-box .md-list { margin: 0 0 10px 18px; padding: 0; }
            .ai-box .md-list li { margin-bottom: 5px; }
            .ai-box .md-rule { border: none; border-top: 1px dashed #d8dce6; margin: 14px 0; }
            .ai-box strong { color: #0b1120; }
            .ai-box code { background: #f1f2f8; color: #4f46e5; padding: 1px 5px; border-radius: 4px; font-size: 11px; }

            table { width: 100%; border-collapse: collapse; font-size: 11.5px; background: #fff; }
            td, th { border: 1px solid #e6e9ef; padding: 9px 12px; text-align: left; }
            th { background: #0b1120; color: #fff; font-weight: 600; font-size: 10px; text-transform: uppercase; letter-spacing: 0.5px; }
            td.key { background: #f8f9fc; font-weight: 600; color: #47526b; width: 30%; }
            td.val { font-family: 'Source Serif 4', serif; }
            .mal-row { background: #fef2f2; color: #991b1b; font-weight: 600; }
            .mal-row td:first-child { border-left: 3px solid #dc2626; }

            .engine-table-wrap { border-radius: 10px; overflow: hidden; box-shadow: 0 3px 12px rgba(15,23,42,0.05); }
            .engine-table-wrap table tr:nth-child(even):not(.mal-row) { background: #fbfbfd; }

            .footer {
              margin-top: 40px;
              padding-top: 16px;
              border-top: 1px solid #e6e9ef;
              display: flex;
              justify-content: space-between;
              font-size: 9px;
              color: #9aa3b2;
              letter-spacing: 0.3px;
            }
            .footer .confidential { font-weight: 700; letter-spacing: 1px; color: #47526b; }

            .disclaimer {
              margin-top: 10px;
              font-size: 9px;
              color: #9aa3b2;
              line-height: 1.5;
              font-style: italic;
            }
          </style>
        </head>
        <body>
          <div class="shape shape-ring"></div>
          <div class="shape shape-ring-sm"></div>
          <div class="shape shape-square"></div>
          <div class="shape shape-tri"></div>
          <div class="shape shape-dots"></div>

          <div class="cover">
            <div class="cover-hex"></div>
            <div class="cover-top">
              <div class="brandmark">
                <div class="mark">C</div>
                <div>
                  <div class="name">CYBERSCIENZA</div>
                  <div class="tagline">Threat Intelligence Division</div>
                </div>
              </div>
              <div class="report-id">
                REPORT REF <b>\${reportId}</b><br/>
                ISSUED <b>\${generatedAtStr}</b>
              </div>
            </div>

            <div class="cover-title">Threat Intelligence Report</div>
            <div class="cover-target">\${activeData.target}<span class="type-chip">\${activeData.kind}</span></div>

            <div class="verdict-strip">
              <div class="verdict-pill">\${statusLabel}</div>
              <div class="verdict-rate">Detection rate<br/><b>\${isNaN(detectionRate) ? 0 : detectionRate}%</b> of \${activeData.total} vendors</div>
            </div>
            <div class="cover-bar"></div>
          </div>

          <div class="content">
            <div class="stats-grid">
              <div class="stat-card stat-mal"><div class="num">\${activeData.malicious}</div><div class="label">Malicious</div></div>
              <div class="stat-card stat-sus"><div class="num">\${activeData.suspicious}</div><div class="label">Suspicious</div></div>
              <div class="stat-card stat-harm"><div class="num">\${activeData.harmless}</div><div class="label">Harmless</div></div>
              <div class="stat-card stat-undet"><div class="num">\${activeData.undetected}</div><div class="label">Undetected</div></div>
            </div>

            <div class="section-head s1"><div class="idx">1</div><h3>AI Threat Assessment</h3><div class="line"></div></div>
            <div class="ai-box">\${aiSections}</div>

            <div class="section-head s2"><div class="idx">2</div><h3>Target Metadata</h3><div class="line"></div></div>
            <table>\${metaRows}</table>

            <div class="section-head s3"><div class="idx">3</div><h3>Vendor Detections (\${(activeData.engines || []).length})</h3><div class="line"></div></div>
            <div class="engine-table-wrap">
              <table>
                <tr><th>Security Vendor</th><th>Verdict</th></tr>
                \${engineRows}
              </table>
            </div>

            <div class="footer">
              <span class="confidential">CYBERSCIENZA · CONFIDENTIAL</span>
              <span>Report \${reportId} · Generated \${generatedAtStr}</span>
            </div>
            <div class="disclaimer">
              This report is generated from automated third-party threat intelligence sources and an AI-assisted summary. It is intended to support, not replace, professional security judgment. Verify findings before taking remediation action.
            </div>
          </div>

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

async function generateOpenRouterAnalysis(vtSummary) {
  const apiKey = OPENROUTER_API_KEY;
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
          temperature: 0.3,
          max_tokens: 800
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

  return `AI Service was unable to respond. Reason: ${lastError || 'unknown error'}`;
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
    }

    start = nextBoundary;
  }
  return { fileObj };
}

const server = http.createServer((req, res) => {
  if (req.method === 'POST' && req.url === '/api/scan') {
    const chunks = [];
    req.on('data', chunk => chunks.push(chunk));
    req.on('end', async () => {
      try {
        const contentType = req.headers['content-type'] || '';
        let result;

        if (contentType.includes('multipart/form-data')) {
          const buffer = Buffer.concat(chunks);
          const boundaryMatch = contentType.match(/boundary=(?:"([^"]+)"|([^;]+))/i);
          const boundary = boundaryMatch ? (boundaryMatch[1] || boundaryMatch[2]) : null;
          const parsed = parseMultipart(buffer, boundary);

          if (!parsed.fileObj) throw new Error("No file payload detected.");
          result = await handleFileScan(parsed.fileObj.data, parsed.fileObj.filename);
        } else {
          const parsed = JSON.parse(Buffer.concat(chunks).toString('utf-8') || '{}');

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

        result.aiAnalysis = await generateOpenRouterAnalysis(result);

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
