/* SentinelForge - Dashboard JS */

const API = {
  async get(path) {
    const r = await fetch(path);
    if (!r.ok) throw new Error(`API error ${r.status}: ${await r.text()}`);
    return r.json();
  },
  async post(path, data) {
    const r = await fetch(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    if (!r.ok) throw new Error(`API error ${r.status}: ${await r.text()}`);
    return r.json();
  }
};

const SEVERITY_COLORS = {
  Critical: '#f85149',
  High: '#db6d28',
  Medium: '#d29922',
  Low: '#3fb950',
  Info: '#58a6ff',
};

const CHART_DEFAULTS = {
  plugins: { legend: { labels: { color: '#8b949e', font: { size: 12 } } } },
  scales: {
    x: { ticks: { color: '#8b949e' }, grid: { color: 'rgba(48,54,61,0.5)' } },
    y: { ticks: { color: '#8b949e' }, grid: { color: 'rgba(48,54,61,0.5)' } },
  }
};

function severityBadge(sev) {
  return `<span class="badge badge-${sev}">${sev}</span>`;
}

function statusDot(status) {
  return `<span class="status-dot status-${status}"></span>${status}`;
}

function timeAgo(iso) {
  if (!iso) return '-';
  const d = new Date(iso);
  const diff = (Date.now() - d.getTime()) / 1000;
  if (diff < 60) return 'just now';
  if (diff < 3600) return `${Math.floor(diff/60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff/3600)}h ago`;
  return d.toLocaleDateString();
}

function truncate(str, n=60) {
  if (!str) return '';
  return str.length > n ? str.slice(0, n) + '…' : str;
}

// ── Overview Dashboard ────────────────────────────────────────────────────────
async function loadOverview() {
  try {
    const stats = await API.get('/stats');
    
    // KPI cards
    if (document.getElementById('total-scans')) {
      document.getElementById('total-scans').textContent = stats.total_scans;
      document.getElementById('total-findings').textContent = stats.total_findings;
      document.getElementById('total-incidents').textContent = stats.total_incidents;
      const sev = stats.severity_counts;
      document.getElementById('critical-count').textContent = sev.Critical || 0;
    }

    // Severity donut
    const ctxDonut = document.getElementById('chart-severity');
    if (ctxDonut) {
      const sev = stats.severity_counts;
      new Chart(ctxDonut, {
        type: 'doughnut',
        data: {
          labels: Object.keys(sev),
          datasets: [{
            data: Object.values(sev),
            backgroundColor: Object.keys(sev).map(s => SEVERITY_COLORS[s] || '#58a6ff'),
            borderColor: '#161b22',
            borderWidth: 2,
          }]
        },
        options: {
          responsive: true, maintainAspectRatio: false,
          plugins: {
            legend: { position: 'right', labels: { color: '#8b949e', font: { size: 11 }, boxWidth: 12 } }
          },
          cutout: '65%',
        }
      });
    }

    // STRIDE bar chart
    const ctxStride = document.getElementById('chart-stride');
    if (ctxStride) {
      const stride = stats.stride_counts;
      const labels = Object.keys(stride);
      new Chart(ctxStride, {
        type: 'bar',
        data: {
          labels,
          datasets: [{
            label: 'Risk Items',
            data: Object.values(stride),
            backgroundColor: '#58a6ff',
            borderRadius: 4,
          }]
        },
        options: {
          responsive: true, maintainAspectRatio: false,
          plugins: { legend: { display: false } },
          scales: {
            x: { ticks: { color: '#8b949e', font: { size: 10 } }, grid: { color: 'rgba(48,54,61,0.4)' } },
            y: { ticks: { color: '#8b949e' }, grid: { color: 'rgba(48,54,61,0.4)' } },
          }
        }
      });
    }

    // NIST CSF Radar
    const ctxNist = document.getElementById('chart-nist');
    if (ctxNist) {
      const nist = stats.nist_counts;
      const nistFunctions = ['Govern', 'Identify', 'Protect', 'Detect', 'Respond', 'Recover'];
      const nistData = nistFunctions.map(f => nist[f] || 0);
      new Chart(ctxNist, {
        type: 'radar',
        data: {
          labels: nistFunctions,
          datasets: [{
            label: 'Risk Items',
            data: nistData,
            backgroundColor: 'rgba(88,166,255,0.15)',
            borderColor: '#58a6ff',
            pointBackgroundColor: '#58a6ff',
            pointRadius: 4,
          }]
        },
        options: {
          responsive: true, maintainAspectRatio: false,
          scales: {
            r: {
              ticks: { color: '#6e7681', backdropColor: 'transparent', font: { size: 10 } },
              grid: { color: 'rgba(48,54,61,0.5)' },
              angleLines: { color: 'rgba(48,54,61,0.5)' },
              pointLabels: { color: '#8b949e', font: { size: 11 } },
            }
          },
          plugins: { legend: { display: false } }
        }
      });
    }

    // Risk trend line
    const ctxTrend = document.getElementById('chart-trend');
    if (ctxTrend && stats.risk_trend.length > 0) {
      const trend = stats.risk_trend;
      new Chart(ctxTrend, {
        type: 'line',
        data: {
          labels: trend.map(t => `#${t.scan_id}`),
          datasets: [{
            label: 'Risk Score',
            data: trend.map(t => t.score),
            borderColor: '#f85149',
            backgroundColor: 'rgba(248,81,73,0.1)',
            fill: true,
            tension: 0.3,
            pointRadius: 4,
            pointBackgroundColor: '#f85149',
          }]
        },
        options: {
          responsive: true, maintainAspectRatio: false,
          plugins: { legend: { display: false } },
          scales: {
            x: { ticks: { color: '#8b949e' }, grid: { color: 'rgba(48,54,61,0.4)' } },
            y: { min: 0, max: 100, ticks: { color: '#8b949e' }, grid: { color: 'rgba(48,54,61,0.4)' } },
          }
        }
      });
    }

  } catch (e) {
    console.error('Failed to load overview:', e);
  }
}

// ── Scan Form ─────────────────────────────────────────────────────────────────
function initScanForm() {
  const form = document.getElementById('scan-form');
  if (!form) return;

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const url = document.getElementById('target-url').value.trim();
    const pattern = document.getElementById('api-pattern').value.trim();
    const idsRaw = document.getElementById('sample-ids').value.trim();
    const sample_ids = idsRaw.split(',').map(s => s.trim()).filter(Boolean);

    const btn = form.querySelector('[type=submit]');
    const resultDiv = document.getElementById('scan-result');

    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> Scanning…';
    resultDiv.innerHTML = '';

    try {
      const scan = await API.post('/scans', {
        target_url: url,
        api_pattern: pattern || '/api/users/{id}',
        sample_ids: sample_ids.length ? sample_ids : ['1', '2', '3'],
        run_bola: true,
      });

      resultDiv.innerHTML = `
        <div class="alert alert-info">
          ✅ Scan #${scan.id} started for <strong>${scan.target_url}</strong>.
          Status: <strong>${scan.status}</strong>.
          <br>Polling for results…
        </div>`;

      // Poll for completion
      await pollScan(scan.id, resultDiv);

    } catch (err) {
      resultDiv.innerHTML = `<div class="alert alert-danger">❌ ${err.message}</div>`;
    } finally {
      btn.disabled = false;
      btn.innerHTML = '🔍 Start Scan';
    }
  });
}

async function pollScan(scanId, container) {
  for (let i = 0; i < 60; i++) {
    await new Promise(r => setTimeout(r, 2000));
    try {
      const scan = await API.get(`/scans/${scanId}`);
      if (scan.status === 'completed') {
        const riskClass = scan.risk_score >= 80 ? 'critical' : scan.risk_score >= 60 ? 'high' : scan.risk_score >= 40 ? 'medium' : 'low';
        container.innerHTML = `
          <div class="alert alert-success">
            ✅ Scan #${scan.id} completed!<br>
            <strong>Findings:</strong> ${scan.finding_count} |
            <strong>Risk Score:</strong> <span class="text-${riskClass}">${scan.risk_score.toFixed(1)}/100</span>
            <br><br>
            <a href="/findings-ui?scan_id=${scan.id}" class="btn btn-primary btn-sm">View Findings</a>
            <a href="/report/${scan.id}?fmt=html" target="_blank" class="btn btn-secondary btn-sm">📄 HTML Report</a>
            <a href="/report/${scan.id}?fmt=md" target="_blank" class="btn btn-secondary btn-sm">📝 Markdown Report</a>
          </div>`;
        return;
      } else if (scan.status === 'failed') {
        container.innerHTML = `<div class="alert alert-danger">❌ Scan failed. Check server logs.</div>`;
        return;
      }
    } catch (e) {
      // keep polling
    }
  }
  container.innerHTML = `<div class="alert alert-warning">⏳ Scan is taking longer than expected. Check /scans/${scanId} manually.</div>`;
}

// ── Findings Table ────────────────────────────────────────────────────────────
async function loadFindings(scanId) {
  const tbody = document.getElementById('findings-tbody');
  if (!tbody) return;

  try {
    let url = '/findings';
    if (scanId) url += `?scan_id=${scanId}`;
    const findings = await API.get(url);

    if (!findings.length) {
      tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted">No findings yet. Run a scan first.</td></tr>';
      return;
    }

    tbody.innerHTML = findings.map(f => `
      <tr>
        <td class="mono">${f.finding_id}</td>
        <td>${truncate(f.title, 50)}</td>
        <td><span class="badge badge-${f.category}" style="background:rgba(88,166,255,0.1);color:#58a6ff;border-color:rgba(88,166,255,0.3)">${f.category}</span></td>
        <td>${severityBadge(f.severity)}</td>
        <td><small>${f.stride_category || '-'}</small></td>
        <td><small>${f.nist_function || '-'}</small></td>
        <td>
          <button class="btn btn-sm btn-secondary" onclick="showFindingDetail(${JSON.stringify(f).replace(/"/g,'&quot;')})">Details</button>
        </td>
      </tr>
    `).join('');
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="7" class="text-center text-critical">Error: ${e.message}</td></tr>`;
  }
}

function showFindingDetail(f) {
  const modal = document.getElementById('finding-modal');
  if (!modal) return;
  document.getElementById('modal-title').textContent = `[${f.finding_id}] ${f.title}`;
  document.getElementById('modal-body').innerHTML = `
    <div class="grid-2">
      <div><strong>Severity:</strong> ${severityBadge(f.severity)}</div>
      <div><strong>Category:</strong> ${f.category}</div>
      <div><strong>STRIDE:</strong> ${f.stride_category || '-'}</div>
      <div><strong>NIST CSF:</strong> ${f.nist_function || '-'}</div>
    </div>
    <hr style="border-color: var(--border-color); margin: 12px 0;">
    <div class="form-group">
      <div class="form-label">Evidence</div>
      <pre class="mono" style="background:var(--bg-tertiary);padding:12px;border-radius:6px;white-space:pre-wrap;font-size:12px;">${f.evidence || 'N/A'}</pre>
    </div>
    <div class="form-group">
      <div class="form-label">Remediation</div>
      <p style="color:var(--text-primary)">${f.remediation || 'N/A'}</p>
    </div>`;
  modal.style.display = 'flex';
}

// ── Threat Intel ──────────────────────────────────────────────────────────────
async function loadIntel(scanId) {
  const container = document.getElementById('intel-container');
  if (!container) return;

  try {
    let url = '/intel';
    if (scanId) url += `?scan_id=${scanId}`;
    const results = await API.get(url);

    if (!results.length) {
      container.innerHTML = '<div class="alert alert-info">No intel results yet. Run a scan first.</div>';
      return;
    }

    container.innerHTML = results.map(ir => {
      const vt = ir.data.virustotal || {};
      const otx = ir.data.otx || {};
      const agg = ir.data.aggregate || {};
      const stats = vt.last_analysis_stats || {};
      const riskColor = ir.reputation_score >= 60 ? 'critical' : ir.reputation_score >= 30 ? 'high' : ir.reputation_score >= 10 ? 'medium' : 'low';

      return `
        <div class="card">
          <div class="flex-between mb-16">
            <div>
              <h3 style="font-size:15px;">${ir.target} ${ir.is_mock ? '<span class="mock-label">MOCK DATA</span>' : ''}</h3>
              <small class="text-muted">Scan #${ir.scan_id} · ${new Date(ir.cached_at).toLocaleString()}</small>
            </div>
            <div class="risk-score">
              <div>
                <div class="risk-score-value text-${riskColor}">${ir.reputation_score.toFixed(0)}</div>
                <div class="risk-score-label">Intel Risk/100</div>
              </div>
            </div>
          </div>
          ${ir.is_mock ? '<div class="alert alert-warning">⚠️ Mock data shown. Add VIRUSTOTAL_API_KEY and OTX_API_KEY to .env for real threat intelligence.</div>' : ''}
          <div class="grid-3">
            <div class="card mb-0">
              <div class="card-title">VirusTotal Detections</div>
              <div style="display:flex;gap:12px;margin-top:8px;">
                <div><div class="card-value text-critical">${stats.malicious || 0}</div><div class="card-sub">Malicious</div></div>
                <div><div class="card-value text-medium">${stats.suspicious || 0}</div><div class="card-sub">Suspicious</div></div>
                <div><div class="card-value text-low">${stats.harmless || 0}</div><div class="card-sub">Harmless</div></div>
              </div>
            </div>
            <div class="card mb-0">
              <div class="card-title">OTX Threat Pulses</div>
              <div class="card-value text-high">${otx.pulse_count || 0}</div>
              <div class="card-sub">Active Pulses</div>
            </div>
            <div class="card mb-0">
              <div class="card-title">Tags</div>
              <div style="margin-top:8px;">${(agg.tags || []).map(t => `<span class="badge" style="background:rgba(88,166,255,0.1);color:#58a6ff;border-color:rgba(88,166,255,0.3);margin:2px">${t}</span>`).join(' ') || '<span class="text-muted">None</span>'}</div>
            </div>
          </div>
        </div>`;
    }).join('');

  } catch (e) {
    container.innerHTML = `<div class="alert alert-danger">Error: ${e.message}</div>`;
  }
}

// ── Risk Register ─────────────────────────────────────────────────────────────
async function loadRiskRegister(scanId) {
  const tbody = document.getElementById('risk-tbody');
  if (!tbody) return;

  try {
    let url = '/risk-register';
    if (scanId) url += `?scan_id=${scanId}`;
    const items = await API.get(url);

    if (!items.length) {
      tbody.innerHTML = '<tr><td colspan="9" class="text-center text-muted">No risk items yet. Run a scan first.</td></tr>';
      return;
    }

    tbody.innerHTML = items.map(r => {
      const scoreColor = r.risk_score >= 80 ? 'critical' : r.risk_score >= 60 ? 'high' : r.risk_score >= 40 ? 'medium' : 'low';
      return `
        <tr>
          <td class="mono">${r.risk_id}</td>
          <td class="truncate">${r.asset}</td>
          <td class="truncate">${truncate(r.threat, 40)}</td>
          <td><small>${r.stride_category}</small></td>
          <td><small>${r.nist_function}</small></td>
          <td><span class="badge badge-${r.likelihood >= 4 ? 'High' : r.likelihood >= 3 ? 'Medium' : 'Low'}">${r.likelihood}/5</span></td>
          <td><span class="badge badge-${r.impact >= 4 ? 'High' : r.impact >= 3 ? 'Medium' : 'Low'}">${r.impact}/5</span></td>
          <td><strong class="text-${scoreColor}">${r.risk_score.toFixed(0)}</strong></td>
          <td><span class="badge badge-${r.treatment === 'Remediate' ? 'Critical' : r.treatment === 'Mitigate' ? 'Medium' : 'Low'}">${r.treatment}</span></td>
        </tr>`;
    }).join('');
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="9" class="text-center text-critical">Error: ${e.message}</td></tr>`;
  }
}

// ── SOAR Incidents ────────────────────────────────────────────────────────────
async function loadIncidents(scanId) {
  const container = document.getElementById('incidents-container');
  if (!container) return;

  try {
    let url = '/incidents';
    if (scanId) url += `?scan_id=${scanId}`;
    const incidents = await API.get(url);

    if (!incidents.length) {
      container.innerHTML = '<div class="alert alert-info">No incidents yet. Run a scan to trigger playbooks.</div>';
      return;
    }

    container.innerHTML = incidents.map(inc => `
      <div class="card">
        <div class="flex-between">
          <div>
            <h3 style="font-size:14px;color:var(--accent-blue)">${inc.playbook_name}</h3>
            <small class="text-muted">Scan #${inc.scan_id} · ${new Date(inc.created_at).toLocaleString()}</small>
          </div>
          <span class="badge badge-Low">${inc.status}</span>
        </div>
        <div style="margin-top:12px;">
          <div class="form-label">Actions Executed</div>
          <div style="margin-top:6px;">
            ${(inc.actions_taken || []).map(a => `
              <div style="display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid var(--border-color);">
                <span style="width:6px;height:6px;background:${a.status==='success'?'var(--accent-green)':'var(--critical)'};border-radius:50%;flex-shrink:0;"></span>
                <code style="font-size:12px;color:var(--accent-blue)">${a.action}</code>
                <span class="text-muted" style="font-size:12px;">→ ${a.status}</span>
              </div>`).join('') || '<span class="text-muted">No actions</span>'}
          </div>
        </div>
      </div>`).join('');
  } catch (e) {
    container.innerHTML = `<div class="alert alert-danger">Error: ${e.message}</div>`;
  }
}

// ── Modal close ───────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  const modal = document.getElementById('finding-modal');
  if (modal) {
    modal.addEventListener('click', (e) => {
      if (e.target === modal) modal.style.display = 'none';
    });
    document.getElementById('modal-close')?.addEventListener('click', () => {
      modal.style.display = 'none';
    });
  }
});
