/**
 * enhancements.js — Six additive features for Automated Threat Modeler.
 *
 * 1. System Templates Library
 * 2. Per-threat Remediation Tracking (status, owner, due date)
 * 3. Risk Matrix Dashboard (likelihood × impact)
 * 4. Severity Bar Chart
 * 5. Threat Model Diff / Version History
 * 6. Attack Path Visualizer
 * 7. Risk Register CSV export button
 *
 * Runs after app.js. Never overrides app.js globals; hooks via safe wrappers.
 */
(function () {
  'use strict';

  /* ────────────────────────────────────────────────────────────────────────
   *  UTILITY
   * ──────────────────────────────────────────────────────────────────────── */
  function esc(s) {
    return typeof escapeHtml === 'function'
      ? escapeHtml(s)
      : String(s || '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[c]);
  }

  function sevColor(s) {
    return {Critical:'#e11d48',High:'#f97316',Medium:'#eab308',Low:'#3b82f6',Info:'#94a3b8'}[s] || '#94a3b8';
  }

  function badge(text, colorClass) {
    return `<span style="display:inline-block;padding:2px 8px;border-radius:99px;font-size:11px;font-weight:600;${colorClass}">${esc(text)}</span>`;
  }

  const TOKEN = () => localStorage.getItem('access_token') || '';
  async function apiFetch(method, url, body) {
    const opts = { method, headers: { Authorization: 'Bearer ' + TOKEN() } };
    if (body) { opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(body); }
    const r = await fetch(url, opts);
    if (!r.ok) { const e = await r.json().catch(() => ({})); throw new Error(e.detail || r.status); }
    return r.json();
  }

  /* ────────────────────────────────────────────────────────────────────────
   *  HOOK: wrap renderResults
   * ──────────────────────────────────────────────────────────────────────── */
  const _origRR = window.renderResults;
  window.renderResults = function (analysis) {
    _origRR && _origRR.call(this, analysis);
    state.lastAnalysis = analysis;
    injectSevChart(analysis);
    injectRiskMatrix(analysis);
    injectRemediationControls(analysis);
    injectAttackPaths(analysis);
    injectExportButtons(analysis);
    injectTicketAndReportButtons(analysis);
    setTimeout(injectCreateTicketButtons, 300);
  };

  /* ════════════════════════════════════════════════════════════════════════
   *  1. SYSTEM TEMPLATES LIBRARY
   * ════════════════════════════════════════════════════════════════════════ */
  let _templates = [];
  let _templatesModal = null;

  function createTemplatesModal() {
    const modal = document.createElement('div');
    modal.id = 'templates-modal';
    modal.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.45);z-index:60;display:flex;align-items:center;justify-content:center;padding:16px;';
    modal.innerHTML = `
      <div style="background:white;border-radius:14px;width:100%;max-width:780px;max-height:85vh;display:flex;flex-direction:column;overflow:hidden;box-shadow:0 20px 60px rgba(0,0,0,.2);">
        <div style="padding:16px 20px;border-bottom:1px solid #e2e8f0;display:flex;align-items:center;justify-content:space-between;flex-shrink:0;">
          <div>
            <h3 style="font-size:16px;font-weight:600;color:#0f172a;margin:0;">System Templates</h3>
            <p style="font-size:12px;color:#64748b;margin:3px 0 0;">Choose a starting point — you can edit everything after loading.</p>
          </div>
          <button id="close-templates-modal" style="font-size:18px;color:#94a3b8;background:none;border:none;cursor:pointer;padding:4px 8px;">✕</button>
        </div>
        <div id="templates-grid" style="padding:16px;overflow-y:auto;display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:12px;"></div>
      </div>
    `;
    document.body.appendChild(modal);
    modal.querySelector('#close-templates-modal').addEventListener('click', () => { modal.style.display = 'none'; });
    modal.addEventListener('click', e => { if (e.target === modal) modal.style.display = 'none'; });
    _templatesModal = modal;
  }

  async function openTemplatesModal() {
    if (!_templatesModal) createTemplatesModal();
    _templatesModal.style.display = 'flex';
    const grid = document.getElementById('templates-grid');
    grid.innerHTML = '<p style="color:#94a3b8;font-size:13px;">Loading…</p>';
    try {
      if (!_templates.length) _templates = await apiFetch('GET', '/api/templates');
      grid.innerHTML = _templates.map((t, i) => `
        <div style="border:1.5px solid #e2e8f0;border-radius:10px;padding:16px;cursor:pointer;transition:border-color .15s;background:white;"
             onmouseenter="this.style.borderColor='#6366f1'"
             onmouseleave="this.style.borderColor='#e2e8f0'"
             onclick="window._loadTemplate(${i})">
          <div style="font-size:24px;margin-bottom:8px;">${esc(t.icon || '🏗️')}</div>
          <div style="font-size:14px;font-weight:600;color:#0f172a;margin-bottom:4px;">${esc(t.name)}</div>
          <div style="font-size:12px;color:#64748b;line-height:1.4;">${esc(t.description)}</div>
          <div style="margin-top:10px;display:flex;gap:6px;flex-wrap:wrap;">
            <span style="font-size:10px;padding:2px 6px;background:#f1f5f9;color:#475569;border-radius:99px;">${t.components.length} components</span>
            <span style="font-size:10px;padding:2px 6px;background:#f1f5f9;color:#475569;border-radius:99px;">${t.data_flows.length} flows</span>
            <span style="font-size:10px;padding:2px 6px;background:#f1f5f9;color:#475569;border-radius:99px;">${t.trust_boundaries.length} zones</span>
          </div>
        </div>
      `).join('');
    } catch (e) {
      grid.innerHTML = `<p style="color:#e11d48;font-size:13px;">Failed to load templates: ${esc(e.message)}</p>`;
    }
  }

  window._loadTemplate = function(idx) {
    const t = _templates[idx];
    if (!t) return;
    state.components = JSON.parse(JSON.stringify(t.components));
    state.data_flows = JSON.parse(JSON.stringify(t.data_flows));
    state.trust_boundaries = JSON.parse(JSON.stringify(t.trust_boundaries));
    state.systemName = t.name;
    state.systemDesc = t.description;
    document.getElementById('builder-system-name').value = t.name;
    document.getElementById('builder-system-desc').value = t.description;
    renderComponents && renderComponents();
    renderFlows && renderFlows();
    if (typeof renderBoundariesList === 'function') renderBoundariesList();
    renderCanvas && renderCanvas();
    document.querySelector('.tab-btn[data-tab="builder"]') && document.querySelector('.tab-btn[data-tab="builder"]').click();
    _templatesModal.style.display = 'none';
    typeof toast === 'function' && toast(`Loaded template: ${t.name}`, 'success');
  };

  // Inject "Templates" button into Step 2 header
  function injectTemplatesButton() {
    const target = document.querySelector('.tab-btn[data-tab="text"]');
    if (!target || document.getElementById('open-templates-btn')) return;
    const btn = document.createElement('button');
    btn.id = 'open-templates-btn';
    btn.textContent = '📐 Templates';
    btn.style.cssText = 'margin-left:auto;padding:6px 14px;background:#6366f1;color:white;border:none;border-radius:6px;font-size:13px;cursor:pointer;font-weight:500;';
    btn.addEventListener('click', openTemplatesModal);
    target.parentElement.appendChild(btn);
  }

  /* ════════════════════════════════════════════════════════════════════════
   *  2. PER-THREAT REMEDIATION TRACKING
   * ════════════════════════════════════════════════════════════════════════ */
  const STATUS_LABELS = {
    open: { label: 'Open', bg: '#fef2f2', color: '#991b1b' },
    in_progress: { label: 'In progress', bg: '#fefce8', color: '#854d0e' },
    mitigated: { label: 'Mitigated', bg: '#f0fdf4', color: '#14532d' },
    accepted_risk: { label: 'Accepted', bg: '#eff6ff', color: '#1e40af' },
    false_positive: { label: 'False positive', bg: '#f8fafc', color: '#475569' },
  };

  let _threatStatuses = {};   // threat_id -> status row

  async function loadThreatStatuses(tmId) {
    if (!tmId) return;
    try {
      const rows = await apiFetch('GET', `/api/threat-status/${tmId}`);
      _threatStatuses = {};
      rows.forEach(r => { _threatStatuses[r.threat_id] = r; });
      updateStatusBadgesInDOM();
    } catch (_) {}
  }

  function updateStatusBadgesInDOM() {
    document.querySelectorAll('[data-threat-status-select]').forEach(sel => {
      const tid = sel.dataset.threatId;
      const row = _threatStatuses[tid];
      if (row) sel.value = row.status;
    });
    document.querySelectorAll('[data-threat-owner-input]').forEach(inp => {
      const tid = inp.dataset.threatId;
      const row = _threatStatuses[tid];
      if (row && row.owner) inp.value = row.owner;
    });
    document.querySelectorAll('[data-threat-due-input]').forEach(inp => {
      const tid = inp.dataset.threatId;
      const row = _threatStatuses[tid];
      if (row && row.due_date) inp.value = row.due_date;
    });
  }

  function remediationHTML(threat) {
    const tid = threat.id || (threat.methodology + '_' + threat.title.slice(0, 20).replace(/\s/g, '_'));
    const row = _threatStatuses[tid] || {};
    const statusKey = row.status || 'open';
    const st = STATUS_LABELS[statusKey] || STATUS_LABELS.open;
    return `
      <div class="remediation-row" style="margin-top:12px;padding:10px 12px;background:#f8fafc;border-radius:8px;border:1px solid #e2e8f0;">
        <div style="font-size:11px;font-weight:600;color:#475569;text-transform:uppercase;letter-spacing:.05em;margin-bottom:8px;">📋 Remediation tracking</div>
        <div style="display:flex;flex-wrap:wrap;gap:8px;align-items:center;">
          <div>
            <label style="font-size:11px;color:#64748b;display:block;margin-bottom:3px;">Status</label>
            <select data-threat-status-select data-threat-id="${esc(tid)}"
                    style="font-size:12px;padding:4px 8px;border:1px solid #e2e8f0;border-radius:5px;background:${st.bg};color:${st.color};cursor:pointer;">
              ${Object.entries(STATUS_LABELS).map(([k, v]) =>
                `<option value="${k}" ${k === statusKey ? 'selected' : ''}>${v.label}</option>`
              ).join('')}
            </select>
          </div>
          <div>
            <label style="font-size:11px;color:#64748b;display:block;margin-bottom:3px;">Owner</label>
            <input type="text" data-threat-owner-input data-threat-id="${esc(tid)}"
                   placeholder="e.g. @alice" value="${esc(row.owner || '')}"
                   style="font-size:12px;padding:4px 8px;border:1px solid #e2e8f0;border-radius:5px;width:130px;"/>
          </div>
          <div>
            <label style="font-size:11px;color:#64748b;display:block;margin-bottom:3px;">Due date</label>
            <input type="date" data-threat-due-input data-threat-id="${esc(tid)}"
                   value="${esc(row.due_date || '')}"
                   style="font-size:12px;padding:4px 8px;border:1px solid #e2e8f0;border-radius:5px;"/>
          </div>
          <div style="align-self:flex-end;">
            <button data-threat-save-btn data-threat-id="${esc(tid)}"
                    style="font-size:12px;padding:5px 12px;background:#0f172a;color:white;border:none;border-radius:5px;cursor:pointer;">Save</button>
          </div>
          ${row.updated_at ? `<div style="font-size:10px;color:#94a3b8;align-self:flex-end;">Last updated ${new Date(row.updated_at).toLocaleDateString()}</div>` : ''}
        </div>
        ${row.notes ? `<div style="font-size:11px;color:#475569;margin-top:6px;"><strong>Notes:</strong> ${esc(row.notes)}</div>` : ''}
      </div>
    `;
  }

  function injectRemediationControls(analysis) {
    const tmId = state.currentProjectId;
    loadThreatStatuses(tmId);
  }

  // Delegate save clicks
  document.addEventListener('click', async e => {
    const btn = e.target.closest('[data-threat-save-btn]');
    if (!btn) return;
    const tid = btn.dataset.threatId;
    const container = btn.closest('.remediation-row');
    const statusEl = container.querySelector('[data-threat-status-select]');
    const ownerEl  = container.querySelector('[data-threat-owner-input]');
    const dueEl    = container.querySelector('[data-threat-due-input]');
    const tmId = state.currentProjectId;
    if (!tmId) { toast && toast('Save the project first to track remediation', 'error'); return; }
    try {
      const result = await apiFetch('POST', '/api/threat-status', {
        threat_id: tid,
        threat_model_id: tmId,
        status: statusEl.value,
        owner: ownerEl.value || null,
        due_date: dueEl.value || null,
      });
      _threatStatuses[tid] = result;
      // Update select styling
      const st = STATUS_LABELS[result.status] || STATUS_LABELS.open;
      statusEl.style.background = st.bg;
      statusEl.style.color = st.color;
      toast && toast('Remediation status saved', 'success');
    } catch (err) {
      toast && toast('Failed: ' + err.message, 'error');
    }
  });

  // status select change → update styling immediately
  document.addEventListener('change', e => {
    const sel = e.target.closest('[data-threat-status-select]');
    if (!sel) return;
    const st = STATUS_LABELS[sel.value] || STATUS_LABELS.open;
    sel.style.background = st.bg;
    sel.style.color = st.color;
  });

  /* ════════════════════════════════════════════════════════════════════════
   *  3. SEVERITY BAR CHART
   * ════════════════════════════════════════════════════════════════════════ */
  function injectSevChart(analysis) {
    let chartWrap = document.getElementById('enh-sev-chart');
    if (!chartWrap) {
      chartWrap = document.createElement('div');
      chartWrap.id = 'enh-sev-chart';
      const anchor = document.getElementById('severity-cards');
      if (anchor && anchor.parentElement) {
        anchor.parentElement.insertBefore(chartWrap, anchor.nextSibling);
      }
    }
    const sum = analysis.summary || {};
    const sevs = ['Critical', 'High', 'Medium', 'Low', 'Info'];
    const counts = sevs.map(s => (sum.by_severity || {})[s] || 0);
    const maxC = Math.max(...counts, 1);
    chartWrap.style.cssText = 'margin:14px 0;padding:14px 16px;background:#f8fafc;border-radius:10px;border:1px solid #e2e8f0;';
    chartWrap.innerHTML = `
      <div style="font-size:11px;font-weight:600;color:#64748b;text-transform:uppercase;letter-spacing:.05em;margin-bottom:10px;">Severity breakdown</div>
      ${sevs.map((s, i) => `
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:5px;">
          <span style="width:68px;text-align:right;font-size:12px;font-weight:600;color:${sevColor(s)}">${s}</span>
          <div style="flex:1;background:#e2e8f0;border-radius:4px;height:16px;overflow:hidden;">
            <div style="width:0%;height:100%;border-radius:4px;background:${sevColor(s)};transition:width .6s cubic-bezier(.34,1.56,.64,1);"
                 data-target="${Math.round((counts[i] / maxC) * 100)}"></div>
          </div>
          <span style="width:20px;font-size:12px;color:#64748b;">${counts[i]}</span>
        </div>
      `).join('')}
    `;
    requestAnimationFrame(() => requestAnimationFrame(() => {
      chartWrap.querySelectorAll('[data-target]').forEach(el => {
        el.style.width = el.dataset.target + '%';
      });
    }));
  }

  /* ════════════════════════════════════════════════════════════════════════
   *  4. RISK MATRIX (Likelihood × Impact)
   * ════════════════════════════════════════════════════════════════════════ */
  const SEV_TO_SCORE = { Critical: 5, High: 4, Medium: 3, Low: 2, Info: 1 };

  function injectRiskMatrix(analysis) {
    let wrap = document.getElementById('enh-risk-matrix');
    if (!wrap) {
      wrap = document.createElement('div');
      wrap.id = 'enh-risk-matrix';
      const anchor = document.getElementById('enh-sev-chart') || document.getElementById('severity-cards');
      if (anchor && anchor.parentElement) {
        anchor.parentElement.insertBefore(wrap, anchor.nextSibling);
      }
    }

    const threats = analysis.threats || [];
    // Map severity → likelihood (DREAD exploitability if available, else heuristic)
    const cells = {};  // "row,col" -> [{title, sev}]
    threats.forEach(t => {
      const impact = SEV_TO_SCORE[t.severity] || 2;
      const dread = t.dread;
      let likelihood = dread ? Math.round(((dread.exploitability || 5) / 10) * 5) : Math.ceil(impact * 0.7);
      likelihood = Math.max(1, Math.min(5, likelihood));
      const key = `${likelihood},${impact}`;
      if (!cells[key]) cells[key] = [];
      cells[key].push(t);
    });

    const LABELS = ['', 'Very Low', 'Low', 'Medium', 'High', 'Very High'];
    const cellColor = (row, col) => {
      const score = row * col;
      if (score >= 16) return '#fef2f2';
      if (score >= 9)  return '#fff7ed';
      if (score >= 4)  return '#fefce8';
      return '#f0fdf4';
    };

    let html = `
      <div style="font-size:11px;font-weight:600;color:#64748b;text-transform:uppercase;letter-spacing:.05em;margin-bottom:10px;">Risk matrix — Likelihood × Impact</div>
      <div style="overflow-x:auto;">
      <table style="border-collapse:collapse;font-size:11px;min-width:360px;width:100%;">
        <thead><tr>
          <th style="padding:4px 8px;color:#94a3b8;text-align:center;"></th>
          ${[1,2,3,4,5].map(c => `<th style="padding:4px 8px;color:#475569;text-align:center;">${LABELS[c]}<br/><span style="font-size:9px;opacity:.6">Impact</span></th>`).join('')}
        </tr></thead>
        <tbody>
          ${[5,4,3,2,1].map(row => `
            <tr>
              <td style="padding:4px 8px;color:#475569;text-align:right;white-space:nowrap;">${LABELS[row]}<br/><span style="font-size:9px;opacity:.6">Likelihood</span></td>
              ${[1,2,3,4,5].map(col => {
                const key = `${row},${col}`;
                const items = cells[key] || [];
                return `<td style="padding:4px;text-align:center;background:${cellColor(row,col)};border:1px solid #e2e8f0;border-radius:4px;cursor:${items.length ? 'pointer' : 'default'};"
                             onclick="${items.length ? `window._showMatrixCell(${JSON.stringify(key)})` : ''}"
                             title="${items.map(t => t.title).join(', ')}">
                  ${items.length ? `<span style="display:inline-block;min-width:22px;height:22px;line-height:22px;background:${sevColor(items[0].severity)};color:white;border-radius:50%;font-size:11px;font-weight:600;">${items.length}</span>` : ''}
                </td>`;
              }).join('')}
            </tr>
          `).join('')}
        </tbody>
      </table>
      </div>
      <p style="font-size:11px;color:#94a3b8;margin-top:6px;">Click any cell to see threats. Numbers = threat count. Color = risk level (🟩 low → 🟥 critical).</p>
    `;

    wrap.style.cssText = 'margin:14px 0;padding:14px 16px;background:#f8fafc;border-radius:10px;border:1px solid #e2e8f0;';
    wrap.innerHTML = html;

    // Store cell data globally for popup
    window._matrixData = cells;
  }

  window._showMatrixCell = function(key) {
    const threats = (window._matrixData || {})[key] || [];
    if (!threats.length) return;
    let popup = document.getElementById('matrix-cell-popup');
    if (!popup) {
      popup = document.createElement('div');
      popup.id = 'matrix-cell-popup';
      popup.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.4);z-index:70;display:flex;align-items:center;justify-content:center;padding:16px;';
      document.body.appendChild(popup);
      popup.addEventListener('click', e => { if (e.target === popup) popup.style.display = 'none'; });
    }
    popup.style.display = 'flex';
    popup.innerHTML = `
      <div style="background:white;border-radius:12px;width:100%;max-width:540px;max-height:70vh;overflow-y:auto;padding:20px;box-shadow:0 16px 48px rgba(0,0,0,.2);">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">
          <h3 style="font-size:15px;font-weight:600;color:#0f172a;margin:0;">${threats.length} threat${threats.length !== 1 ? 's' : ''} in this cell</h3>
          <button onclick="document.getElementById('matrix-cell-popup').style.display='none'" style="background:none;border:none;font-size:18px;cursor:pointer;color:#64748b;">✕</button>
        </div>
        ${threats.map(t => `
          <div style="padding:10px 12px;border:1px solid #e2e8f0;border-radius:8px;margin-bottom:8px;border-left:3px solid ${sevColor(t.severity)};">
            <div style="font-size:13px;font-weight:600;color:#0f172a;margin-bottom:3px;">${esc(t.title)}</div>
            <div style="font-size:11px;color:#64748b;">${esc(t.component_name)} · ${esc(t.methodology.toUpperCase())} · ${esc(t.severity)}</div>
          </div>
        `).join('')}
      </div>
    `;
  };

  /* ════════════════════════════════════════════════════════════════════════
   *  5. ATTACK PATH VISUALIZER
   * ════════════════════════════════════════════════════════════════════════ */
  function injectAttackPaths(analysis) {
    let wrap = document.getElementById('enh-attack-paths');
    if (!wrap) {
      wrap = document.createElement('div');
      wrap.id = 'enh-attack-paths';
      const anchor = document.getElementById('enh-risk-matrix') || document.getElementById('enh-sev-chart');
      if (anchor && anchor.nextSibling) {
        anchor.parentElement.insertBefore(wrap, anchor.nextSibling);
      } else if (anchor) {
        anchor.parentElement.appendChild(wrap);
      }
    }

    // Build attack paths: group threats by component, find cross-boundary chains
    const threats = analysis.threats || [];
    const components = (state.components || []);
    const flows = (state.data_flows || []);
    const boundaries = (state.trust_boundaries || []);

    // Entry points = external_entity or user with cross-boundary flows
    const entryIds = new Set(
      components.filter(c => ['user', 'external_entity', 'mobile_app'].includes(c.type)).map(c => c.id)
    );

    // Build adjacency: component id -> array of reachable component ids
    const adj = {};
    flows.forEach(f => {
      if (!adj[f.from]) adj[f.from] = [];
      adj[f.from].push({ to: f.to, flow: f });
    });

    // Find top chains: entry → any path of length 2-3 that crosses a trust boundary
    const paths = [];
    entryIds.forEach(start => {
      const startComp = components.find(c => c.id === start);
      if (!startComp) return;
      const startThreats = threats.filter(t => t.component_id === start || t.component_name === startComp.name);
      // Follow outgoing flows
      (adj[start] || []).forEach(({ to: mid, flow: f1 }) => {
        const midComp = components.find(c => c.id === mid);
        if (!midComp) return;
        const midThreats = threats.filter(t => t.component_id === mid || t.component_name === midComp.name);
        const crossesBoundary = boundaries.some(b =>
          b.contains.includes(start) !== b.contains.includes(mid)
        );
        const highSev = [...startThreats, ...midThreats].filter(t => ['Critical','High'].includes(t.severity));
        if (highSev.length === 0) return;
        // Try to extend one more hop
        (adj[mid] || []).forEach(({ to: dest, flow: f2 }) => {
          const destComp = components.find(c => c.id === dest);
          if (!destComp || dest === start) return;
          const destThreats = threats.filter(t => t.component_id === dest || t.component_name === destComp.name);
          const allThreats = [...startThreats, ...midThreats, ...destThreats];
          const critCount = allThreats.filter(t => t.severity === 'Critical').length;
          paths.push({
            nodes: [startComp, midComp, destComp],
            flows: [f1, f2],
            threats: allThreats,
            critCount,
            crossesBoundary,
          });
        });
        if (!(adj[mid] || []).length) {
          paths.push({
            nodes: [startComp, midComp],
            flows: [f1],
            threats: [...startThreats, ...midThreats],
            critCount: [...startThreats, ...midThreats].filter(t => t.severity === 'Critical').length,
            crossesBoundary,
          });
        }
      });
    });

    // Deduplicate by node path and sort by critCount desc
    const seen = new Set();
    const unique = paths.filter(p => {
      const key = p.nodes.map(n => n.id).join('→');
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    }).sort((a, b) => b.critCount - a.critCount).slice(0, 5);

    if (!unique.length) { wrap.innerHTML = ''; return; }

    wrap.style.cssText = 'margin:14px 0;padding:14px 16px;background:#fff7ed;border-radius:10px;border:1px solid #fed7aa;';
    wrap.innerHTML = `
      <div style="font-size:11px;font-weight:600;color:#9a3412;text-transform:uppercase;letter-spacing:.05em;margin-bottom:10px;">⚡ Top attack paths</div>
      <p style="font-size:12px;color:#7c3012;margin:0 0 10px;">Multi-hop paths an attacker could follow through your system, ordered by severity.</p>
      ${unique.map((path, idx) => `
        <div style="background:white;border:1px solid #fed7aa;border-left:3px solid ${path.critCount > 0 ? '#e11d48' : '#f97316'};border-radius:8px;padding:12px;margin-bottom:8px;">
          <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:6px;">
            ${path.nodes.map((n, i) => `
              <span style="font-size:12px;font-weight:600;color:#0f172a;background:#f8fafc;padding:3px 8px;border-radius:4px;border:1px solid #e2e8f0;">${esc(n.name)}</span>
              ${i < path.nodes.length - 1 ? `<span style="color:#94a3b8;font-size:14px;">${path.flows[i] && !path.flows[i].encrypted ? '⚠→' : '→'}</span>` : ''}
            `).join('')}
            ${path.crossesBoundary ? '<span style="font-size:10px;padding:2px 6px;background:#fef2f2;color:#991b1b;border-radius:99px;">crosses trust boundary</span>' : ''}
          </div>
          <div style="font-size:11px;color:#64748b;">
            ${path.threats.length} threats ·
            ${path.critCount > 0 ? `<span style="color:#e11d48;font-weight:600;">${path.critCount} Critical</span> · ` : ''}
            Entry: <strong>${esc(path.nodes[0].type)}</strong> →
            Target: <strong>${esc(path.nodes[path.nodes.length - 1].type)}</strong>
          </div>
          <div style="margin-top:6px;display:flex;flex-wrap:wrap;gap:4px;">
            ${path.threats.filter(t => ['Critical','High'].includes(t.severity)).slice(0, 3).map(t =>
              `<span style="font-size:10px;padding:2px 6px;background:${sevColor(t.severity)}22;color:${sevColor(t.severity)};border-radius:99px;border:1px solid ${sevColor(t.severity)}44;">${esc(t.title.slice(0, 40))}…</span>`
            ).join('')}
          </div>
        </div>
      `).join('')}
    `;
  }

  /* ════════════════════════════════════════════════════════════════════════
   *  6. EXPORT BUTTONS (CSV + HTML already exists, adding CSV)
   * ════════════════════════════════════════════════════════════════════════ */
  function injectExportButtons(analysis) {
    const dlBar = document.querySelector('#results .flex.gap-2');
    if (!dlBar || document.getElementById('dl-csv-btn')) return;
    const btn = document.createElement('button');
    btn.id = 'dl-csv-btn';
    btn.textContent = '↓ Risk Register CSV';
    btn.style.cssText = 'padding:6px 12px;font-size:13px;border:1px solid #d1fae5;background:#ecfdf5;color:#065f46;border-radius:6px;cursor:pointer;font-weight:500;';
    btn.addEventListener('click', async () => {
      try {
        const r = await fetch('/api/report/csv', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + TOKEN() },
          body: JSON.stringify(analysis),
        });
        const blob = await r.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url; a.download = 'risk_register.csv';
        document.body.appendChild(a); a.click(); a.remove();
        URL.revokeObjectURL(url);
        toast && toast('Downloaded risk register CSV', 'success');
      } catch (e) {
        toast && toast('CSV export failed: ' + e.message, 'error');
      }
    });
    dlBar.insertBefore(btn, dlBar.firstChild);
  }

  /* ════════════════════════════════════════════════════════════════════════
   *  7. THREAT MODEL DIFF / VERSION HISTORY
   * ════════════════════════════════════════════════════════════════════════ */
  function injectDiffButton() {
    const saveBtn = document.getElementById('save-project-btn');
    if (!saveBtn || document.getElementById('diff-history-btn')) return;
    const btn = document.createElement('button');
    btn.id = 'diff-history-btn';
    btn.textContent = '🕐 Version history';
    btn.style.cssText = 'padding:8px 16px;border:1px solid #e2e8f0;border-radius:6px;font-size:13px;cursor:pointer;background:white;';
    btn.addEventListener('click', openDiffModal);
    saveBtn.parentElement.insertBefore(btn, saveBtn);
  }

  let _diffModal = null;

  async function openDiffModal() {
    if (!_diffModal) {
      _diffModal = document.createElement('div');
      _diffModal.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.45);z-index:60;display:flex;align-items:center;justify-content:center;padding:16px;';
      _diffModal.innerHTML = `
        <div style="background:white;border-radius:14px;width:100%;max-width:720px;max-height:80vh;display:flex;flex-direction:column;overflow:hidden;box-shadow:0 20px 60px rgba(0,0,0,.2);">
          <div style="padding:16px 20px;border-bottom:1px solid #e2e8f0;display:flex;justify-content:space-between;align-items:center;flex-shrink:0;">
            <div>
              <h3 style="font-size:16px;font-weight:600;color:#0f172a;margin:0;">Version history</h3>
              <p style="font-size:12px;color:#64748b;margin:3px 0 0;">Threat status changes and model snapshots over time.</p>
            </div>
            <button id="close-diff-modal" style="font-size:18px;color:#94a3b8;background:none;border:none;cursor:pointer;">✕</button>
          </div>
          <div id="diff-body" style="padding:16px;overflow-y:auto;flex:1;"></div>
        </div>
      `;
      document.body.appendChild(_diffModal);
      _diffModal.querySelector('#close-diff-modal').addEventListener('click', () => { _diffModal.style.display = 'none'; });
      _diffModal.addEventListener('click', e => { if (e.target === _diffModal) _diffModal.style.display = 'none'; });
    }
    _diffModal.style.display = 'flex';
    const body = document.getElementById('diff-body');
    body.innerHTML = '<p style="color:#94a3b8;font-size:13px;">Loading…</p>';

    const tmId = state.currentProjectId;
    if (!tmId) {
      body.innerHTML = `
        <div style="text-align:center;padding:32px;color:#64748b;">
          <div style="font-size:32px;margin-bottom:8px;">💾</div>
          <p style="font-size:14px;font-weight:500;">Save this project first</p>
          <p style="font-size:12px;color:#94a3b8;">Version history is available after saving a threat model project.</p>
        </div>`;
      return;
    }

    try {
      const statuses = await apiFetch('GET', `/api/threat-status/${tmId}`);
      if (!statuses.length) {
        body.innerHTML = '<p style="color:#94a3b8;font-size:13px;text-align:center;padding:24px;">No threat status changes recorded yet. Start tracking remediation to build history.</p>';
        return;
      }

      const byDate = {};
      statuses.forEach(s => {
        const day = (s.updated_at || '').slice(0, 10);
        if (!byDate[day]) byDate[day] = [];
        byDate[day].push(s);
      });

      body.innerHTML = Object.entries(byDate).sort((a,b) => b[0].localeCompare(a[0])).map(([day, items]) => `
        <div style="margin-bottom:16px;">
          <div style="font-size:12px;font-weight:600;color:#64748b;margin-bottom:8px;padding-bottom:4px;border-bottom:1px solid #f1f5f9;">${day}</div>
          ${items.map(s => `
            <div style="display:flex;align-items:center;gap:10px;padding:6px 10px;border-radius:6px;margin-bottom:4px;background:#f8fafc;border:1px solid #e2e8f0;">
              <span style="font-size:11px;padding:2px 8px;border-radius:99px;background:${(STATUS_LABELS[s.status] || STATUS_LABELS.open).bg};color:${(STATUS_LABELS[s.status] || STATUS_LABELS.open).color};font-weight:600;">${(STATUS_LABELS[s.status] || STATUS_LABELS.open).label}</span>
              <span style="font-size:12px;color:#0f172a;flex:1;">${esc(s.threat_id)}</span>
              ${s.owner ? `<span style="font-size:11px;color:#64748b;">👤 ${esc(s.owner)}</span>` : ''}
              ${s.due_date ? `<span style="font-size:11px;color:#64748b;">📅 ${esc(s.due_date)}</span>` : ''}
              ${s.time_to_closure_seconds ? `<span style="font-size:11px;color:#16a34a;">✓ closed in ${Math.round(s.time_to_closure_seconds / 3600)}h</span>` : ''}
            </div>
          `).join('')}
        </div>
      `).join('');
    } catch (e) {
      body.innerHTML = `<p style="color:#e11d48;font-size:13px;">Failed to load history: ${esc(e.message)}</p>`;
    }
  }

  /* ════════════════════════════════════════════════════════════════════════
   *  PATCH _renderThreatCard to append remediation row
   * ════════════════════════════════════════════════════════════════════════ */
  const _origRTC = window._renderThreatCard;
  if (_origRTC) {
    window._renderThreatCard = function(t, idx) {
      const html = _origRTC.call(this, t, idx);
      const tid = t.id || (t.methodology + '_' + t.title.slice(0, 20).replace(/\s/g, '_'));
      const remHtml = remediationHTML({...t, id: tid});
      // Insert before closing div of .threat-card-detail
      return html.replace('</div>\n  </div>', `${remHtml}</div>\n  </div>`);
    };
  }

  /* ════════════════════════════════════════════════════════════════════════
   *  INIT
   * ════════════════════════════════════════════════════════════════════════ */
  function init() {
    injectTemplatesButton();
    injectDiffButton();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  /* ════════════════════════════════════════════════════════════════════════
   *  U4 — Keyboard shortcuts for DFD builder
   * ════════════════════════════════════════════════════════════════════════ */
  function initKeyboardShortcuts() {
    document.addEventListener('keydown', e => {
      // Don't fire inside inputs / textareas
      if (['INPUT','TEXTAREA','SELECT'].includes(document.activeElement.tagName)) return;
      if (e.target.isContentEditable) return;

      switch (e.key) {
        case 'n': document.getElementById('add-component-btn') && document.getElementById('add-component-btn').click(); break;
        case 'f': document.getElementById('add-flow-btn') && document.getElementById('add-flow-btn').click(); break;
        case 'b': document.getElementById('add-boundary-btn') && document.getElementById('add-boundary-btn').click(); break;
        case 'a': document.getElementById('auto-layout-btn') && document.getElementById('auto-layout-btn').click(); break;
        case '?': showShortcutsHelp(); break;
        case 'Escape': closeShortcutsHelp(); break;
        default:
          if ((e.ctrlKey || e.metaKey) && e.key === 's') { e.preventDefault(); document.getElementById('save-project-btn') && document.getElementById('save-project-btn').click(); }
          break;
      }
    });

    // Add ? button to DFD toolbar
    const toolbar = document.querySelector('#dfd-canvas-wrap')?.previousElementSibling;
    if (toolbar && !document.getElementById('shortcuts-btn')) {
      const btn = document.createElement('button');
      btn.id = 'shortcuts-btn';
      btn.textContent = '?';
      btn.title = 'Keyboard shortcuts';
      btn.style.cssText = 'padding:4px 8px;border:1px solid #e2e8f0;border-radius:5px;font-size:11px;cursor:pointer;background:white;margin-left:4px;';
      btn.addEventListener('click', showShortcutsHelp);
      toolbar.querySelector('.flex.items-center.gap-1\.5') && toolbar.querySelector('.flex.items-center.gap-1\.5').appendChild(btn);
    }
  }

  function showShortcutsHelp() {
    if (document.getElementById('shortcuts-modal')) { document.getElementById('shortcuts-modal').style.display = 'flex'; return; }
    const m = document.createElement('div');
    m.id = 'shortcuts-modal';
    m.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.45);z-index:80;display:flex;align-items:center;justify-content:center;';
    m.innerHTML = `<div style="background:white;border-radius:12px;padding:24px;width:360px;box-shadow:0 16px 48px rgba(0,0,0,.2);">
      <h3 style="font-size:15px;font-weight:700;margin-bottom:14px;">⌨ Keyboard shortcuts</h3>
      ${[['n','Add component'],['f','Add data flow'],['b','Add trust boundary'],
         ['a','Auto-layout DFD'],['Ctrl+S','Save project'],['?','Show this help'],['Esc','Close modals']]
        .map(([k,v])=>`<div style="display:flex;justify-content:space-between;padding:5px 0;border-bottom:1px solid #f1f5f9;font-size:13px;">
          <span style="color:#64748b;">${v}</span>
          <kbd style="background:#f1f5f9;padding:2px 8px;border-radius:4px;font-family:monospace;font-size:11px;">${k}</kbd>
        </div>`).join('')}
      <button onclick="document.getElementById('shortcuts-modal').style.display='none'"
              style="margin-top:14px;width:100%;padding:8px;background:#0f172a;color:white;border:none;border-radius:6px;cursor:pointer;font-size:13px;">Close</button>
    </div>`;
    m.addEventListener('click', e => { if (e.target === m) m.style.display = 'none'; });
    document.body.appendChild(m);
  }
  function closeShortcutsHelp() {
    const m = document.getElementById('shortcuts-modal');
    if (m) m.style.display = 'none';
  }

  /* ════════════════════════════════════════════════════════════════════════
   *  U5 — Dark / light mode toggle
   * ════════════════════════════════════════════════════════════════════════ */
  function initDarkMode() {
    const stored = localStorage.getItem('atm-theme') || 'light';
    document.documentElement.setAttribute('data-theme', stored);

    const btn = document.createElement('button');
    btn.id = 'theme-toggle';
    btn.title = 'Toggle dark/light mode';
    btn.style.cssText = 'background:none;border:none;cursor:pointer;font-size:18px;padding:4px 8px;';
    btn.textContent = stored === 'dark' ? '☀️' : '🌙';
    btn.addEventListener('click', () => {
      const curr = document.documentElement.getAttribute('data-theme');
      const next = curr === 'dark' ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', next);
      localStorage.setItem('atm-theme', next);
      btn.textContent = next === 'dark' ? '☀️' : '🌙';
    });

    // Inject into header
    const headerFlex = document.querySelector('header .flex.items-center.gap-3');
    if (headerFlex) headerFlex.insertBefore(btn, headerFlex.firstChild);

    // Inject minimal dark-mode CSS
    if (!document.getElementById('dark-mode-style')) {
      const style = document.createElement('style');
      style.id = 'dark-mode-style';
      style.textContent = `
        [data-theme="dark"] body { background: #0f172a !important; color: #e2e8f0 !important; }
        [data-theme="dark"] .bg-white { background: #1e293b !important; }
        [data-theme="dark"] .bg-slate-50 { background: #0f172a !important; }
        [data-theme="dark"] .border-slate-200 { border-color: #334155 !important; }
        [data-theme="dark"] .text-slate-900 { color: #f1f5f9 !important; }
        [data-theme="dark"] .text-slate-500, [data-theme="dark"] .text-slate-600 { color: #94a3b8 !important; }
        [data-theme="dark"] input, [data-theme="dark"] textarea, [data-theme="dark"] select {
          background: #1e293b !important; color: #e2e8f0 !important; border-color: #475569 !important;
        }
        [data-theme="dark"] .threat-card { background: #1e293b !important; border-color: #334155 !important; }
        [data-theme="dark"] #dfd-canvas { background: #0f172a !important; }
      `;
      document.head.appendChild(style);
    }
  }

  /* ════════════════════════════════════════════════════════════════════════
   *  U2 — Bulk threat status select-all + update
   * ════════════════════════════════════════════════════════════════════════ */
  function injectBulkStatusUI(analysis) {
    const filterBar = document.querySelector('#results .flex.flex-wrap.gap-2.mb-4');
    if (!filterBar || document.getElementById('bulk-update-btn')) return;

    const selectAll = document.createElement('button');
    selectAll.id = 'select-all-low';
    selectAll.textContent = '☑ Select all Low/Info';
    selectAll.style.cssText = 'font-size:11px;padding:4px 10px;border:1px solid #e2e8f0;border-radius:99px;cursor:pointer;background:white;';
    selectAll.addEventListener('click', () => {
      document.querySelectorAll('[data-threat-status-select]').forEach(sel => {
        const card = sel.closest('[data-threat-sev]');
        if (card && ['Low','Info'].includes(card.dataset.threatSev)) {
          sel.value = 'accepted_risk';
          sel.dispatchEvent(new Event('change'));
          sel.dataset.selected = '1';
        }
      });
      toast && toast('Low/Info threats selected — click "Bulk save" to apply', 'info');
    });

    const bulkBtn = document.createElement('button');
    bulkBtn.id = 'bulk-update-btn';
    bulkBtn.textContent = '💾 Bulk save';
    bulkBtn.style.cssText = 'font-size:11px;padding:4px 10px;border:1px solid #6366f1;background:#eff6ff;color:#1e40af;border-radius:99px;cursor:pointer;font-weight:600;';
    bulkBtn.addEventListener('click', async () => {
      const tmId = state.currentProjectId;
      if (!tmId) { toast && toast('Save project first to use bulk update', 'error'); return; }
      const updates = [];
      document.querySelectorAll('[data-threat-status-select]').forEach(sel => {
        if (sel.dataset.selected) {
          updates.push({ threat_id: sel.dataset.threatId, status: sel.value });
          delete sel.dataset.selected;
        }
      });
      if (!updates.length) { toast && toast('No threats selected', 'info'); return; }
      try {
        bulkBtn.textContent = 'Saving…'; bulkBtn.disabled = true;
        const r = await fetch('/api/threat-status/bulk', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + TOKEN() },
          body: JSON.stringify({ threat_model_id: tmId, updates }),
        });
        const res = await r.json();
        toast && toast(`✓ ${res.updated} threats updated`, 'success');
      } catch (e) {
        toast && toast('Bulk update failed: ' + e.message, 'error');
      } finally { bulkBtn.textContent = '💾 Bulk save'; bulkBtn.disabled = false; }
    });

    filterBar.appendChild(selectAll);
    filterBar.appendChild(bulkBtn);
  }

  /* ════════════════════════════════════════════════════════════════════════
   *  U3 — Share link button
   * ════════════════════════════════════════════════════════════════════════ */
  function injectShareButton(analysis) {
    const dlBar = document.querySelector('#results .flex.gap-2');
    if (!dlBar || document.getElementById('share-link-btn')) return;

    const btn = document.createElement('button');
    btn.id = 'share-link-btn';
    btn.textContent = '🔗 Share';
    btn.style.cssText = 'padding:6px 12px;font-size:13px;border:1px solid #e2e8f0;border-radius:6px;cursor:pointer;background:white;';
    btn.addEventListener('click', async () => {
      const tmId = state.currentProjectId;
      if (!tmId) { toast && toast('Save the project first to generate a share link', 'error'); return; }
      try {
        btn.textContent = 'Generating…'; btn.disabled = true;
        const r = await fetch(`/api/share/${tmId}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + TOKEN() },
          body: JSON.stringify({ expires_days: 7 }),
        });
        const { url } = await r.json();
        await navigator.clipboard.writeText(url).catch(() => {});
        toast && toast('Share link copied to clipboard! Expires in 7 days.', 'success');
        prompt('Share this link (read-only, 7 days):', url);
      } catch (e) {
        toast && toast('Failed to generate share link: ' + e.message, 'error');
      } finally { btn.textContent = '🔗 Share'; btn.disabled = false; }
    });
    dlBar.appendChild(btn);
  }

  /* ════════════════════════════════════════════════════════════════════════
   *  ATT&CK badge + Compliance section per threat card
   * ════════════════════════════════════════════════════════════════════════ */
  function injectAttackAndCompliance() {
    document.querySelectorAll('[data-threat-idx]').forEach(card => {
      if (card.querySelector('.attack-badge')) return;
      const idx = card.dataset.threatIdx;
      const t = state.lastAnalysis && state.lastAnalysis.threats && state.lastAnalysis.threats[+idx];
      if (!t) return;

      // ATT&CK badge
      if (t.attack) {
        const badge = document.createElement('a');
        badge.className = 'attack-badge';
        badge.href = `https://attack.mitre.org/techniques/${t.attack.id.replace('.','/')}/`;
        badge.target = '_blank';
        badge.rel = 'noopener';
        badge.style.cssText = 'display:inline-flex;align-items:center;gap:4px;font-size:10px;padding:2px 8px;background:#1e0936;color:#c4b5fd;border:1px solid #6d28d9;border-radius:99px;text-decoration:none;margin-left:4px;';
        badge.innerHTML = `🎯 ${esc(t.attack.id)} · ${esc(t.attack.tactic)}`;
        const header = card.querySelector('.threat-card-header') || card.querySelector('.flex.items-center.gap-1');
        if (header) header.appendChild(badge);
      }

      // Compliance in expanded body
      if (t.compliance && Object.keys(t.compliance).length) {
        const body = card.querySelector('.threat-card-body, .threat-card-detail');
        if (body && !body.querySelector('.compliance-section')) {
          const div = document.createElement('div');
          div.className = 'compliance-section';
          div.style.cssText = 'margin-top:10px;padding:8px 12px;background:#f8fafc;border-radius:6px;border:1px solid #e2e8f0;font-size:11px;';
          div.innerHTML = '<div style="font-weight:600;color:#475569;margin-bottom:5px;text-transform:uppercase;letter-spacing:.04em;">📋 Compliance controls</div>' +
            Object.entries(t.compliance).map(([fw, ids]) =>
              `<div style="margin-bottom:3px;"><span style="color:#64748b;font-weight:600;">${esc(fw.toUpperCase())}:</span> ${ids.map(id => `<code style="background:#eff6ff;color:#1e40af;padding:1px 5px;border-radius:3px;font-size:10px;">${esc(id)}</code>`).join(' ')}</div>`
            ).join('');
          body.appendChild(div);
        }
      }
    });
  }

  /* ════════════════════════════════════════════════════════════════════════
   *  P2 — "Fix this" AI code snippet button per threat
   * ════════════════════════════════════════════════════════════════════════ */
  function injectFixButtons() {
    document.querySelectorAll('[data-threat-idx]').forEach(card => {
      if (card.querySelector('.fix-btn')) return;
      const idx = card.dataset.threatIdx;
      const header = card.querySelector('.threat-card-header') || card.querySelector('.flex.items-center');
      if (!header) return;

      const btn = document.createElement('button');
      btn.className = 'fix-btn';
      btn.textContent = '🔧 Fix';
      btn.title = 'Generate AI code fix for this threat';
      btn.style.cssText = 'background:none;border:1px solid #e2e8f0;border-radius:4px;padding:2px 7px;cursor:pointer;font-size:11px;margin-left:4px;flex-shrink:0;';
      btn.addEventListener('click', async e => {
        e.stopPropagation();
        const t = state.lastAnalysis && state.lastAnalysis.threats && state.lastAnalysis.threats[+idx];
        if (!t) return;
        btn.textContent = '⏳'; btn.disabled = true;
        try {
          const r = await fetch('/api/threat/fix', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + TOKEN() },
            body: JSON.stringify({ threat: t, system_name: state.systemName || 'System', tech_stack: state.systemDesc || '' }),
          });
          if (!r.ok) { const err = await r.json(); throw new Error(err.detail); }
          const fix = await r.json();
          showFixModal(t.title, fix);
        } catch (err) {
          toast && toast('Fix generation failed: ' + err.message, 'error');
        } finally { btn.textContent = '🔧 Fix'; btn.disabled = false; }
      });
      header.appendChild(btn);
    });
  }

  function showFixModal(title, fix) {
    let modal = document.getElementById('fix-modal');
    if (!modal) {
      modal = document.createElement('div');
      modal.id = 'fix-modal';
      modal.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.45);z-index:80;display:flex;align-items:center;justify-content:center;padding:16px;';
      modal.addEventListener('click', e => { if (e.target === modal) modal.style.display = 'none'; });
      document.body.appendChild(modal);
    }
    modal.style.display = 'flex';
    modal.innerHTML = `<div style="background:white;border-radius:14px;width:100%;max-width:680px;max-height:85vh;overflow-y:auto;padding:24px;box-shadow:0 20px 60px rgba(0,0,0,.2);">
      <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:16px;">
        <div>
          <div style="font-size:15px;font-weight:700;color:#0f172a;">🔧 AI-generated fix</div>
          <div style="font-size:12px;color:#64748b;margin-top:2px;">${esc(title)}</div>
        </div>
        <button onclick="document.getElementById('fix-modal').style.display='none'"
                style="background:none;border:none;font-size:18px;cursor:pointer;color:#94a3b8;">✕</button>
      </div>
      <div style="background:#f0fdf4;border:1px solid #bbf7d0;border-radius:8px;padding:10px 14px;font-size:13px;color:#15803d;margin-bottom:14px;">
        ${esc(fix.explanation || '')}
      </div>
      <div style="font-size:12px;font-weight:600;color:#ef4444;margin-bottom:6px;">Before (vulnerable)</div>
      <pre style="background:#0f172a;color:#e2e8f0;padding:14px;border-radius:8px;font-size:12px;overflow-x:auto;margin-bottom:12px;">${esc(fix.before || '')}</pre>
      <div style="font-size:12px;font-weight:600;color:#16a34a;margin-bottom:6px;">After (fixed)</div>
      <pre style="background:#0f172a;color:#e2e8f0;padding:14px;border-radius:8px;font-size:12px;overflow-x:auto;margin-bottom:12px;">${esc(fix.after || '')}</pre>
      ${fix.diff_summary ? `<div style="font-size:12px;color:#475569;background:#f8fafc;border-radius:6px;padding:10px 14px;">${esc(fix.diff_summary)}</div>` : ''}
      <button onclick="navigator.clipboard.writeText(${JSON.stringify(fix.after || '')}).then(()=>{ this.textContent='✓ Copied'; setTimeout(()=>{this.textContent='Copy fixed code'},2000) })"
              style="margin-top:14px;width:100%;padding:9px;background:#0f172a;color:white;border:none;border-radius:6px;cursor:pointer;font-size:13px;">Copy fixed code</button>
    </div>`;
  }

  /* ── patch renderResults to wire in new UI pieces ── */
  const _prevRR = window.renderResults;
  window.renderResults = function(analysis) {
    _prevRR && _prevRR.call(this, analysis);
    injectBulkStatusUI(analysis);
    injectShareButton(analysis);
    setTimeout(() => {
      injectAttackAndCompliance();
      injectFixButtons();
    }, 350);
  };

  /* ── init on load ── */
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => { initKeyboardShortcuts(); initDarkMode(); });
  } else {
    initKeyboardShortcuts(); initDarkMode();
  }


  /* ════════════════════════════════════════════════════════════════════════
   *  E5 — Custom threat rules CRUD (UI wiring)
   * ════════════════════════════════════════════════════════════════════════ */
  async function initCustomRulesTab() {
    const saveBtn = document.getElementById('save-custom-rule-btn');
    if (!saveBtn || saveBtn.dataset.wired) return;
    saveBtn.dataset.wired = '1';

    await loadCustomRules();

    saveBtn.addEventListener('click', async () => {
      const title = document.getElementById('rule-title').value.trim();
      const name  = document.getElementById('rule-name').value.trim() || title;
      if (!title) { toast && toast('Enter a threat title', 'error'); return; }

      const payload = {
        name, title,
        severity:    document.getElementById('rule-severity').value,
        category:    document.getElementById('rule-category').value || 'Custom',
        description: document.getElementById('rule-description').value.trim(),
        mitigations: document.getElementById('rule-mitigations').value
                       .split('
').map(s => s.trim()).filter(Boolean),
        applies_to:  document.getElementById('rule-applies-to').value
                       .split(',').map(s => s.trim()).filter(Boolean),
      };
      try {
        saveBtn.textContent = 'Saving…'; saveBtn.disabled = true;
        const r = await fetch('/api/custom-rules', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + TOKEN() },
          body: JSON.stringify(payload),
        });
        if (!r.ok) throw new Error((await r.json()).detail || r.status);
        toast && toast('Custom rule saved ✓', 'success');
        ['rule-name','rule-title','rule-description','rule-mitigations','rule-applies-to'].forEach(id => {
          const el = document.getElementById(id); if (el) el.value = '';
        });
        await loadCustomRules();
      } catch (e) {
        toast && toast('Failed: ' + e.message, 'error');
      } finally { saveBtn.textContent = '+ Save rule'; saveBtn.disabled = false; }
    });
  }

  async function loadCustomRules() {
    const list = document.getElementById('custom-rules-list');
    const count = document.getElementById('rules-count');
    if (!list) return;
    try {
      const r = await fetch('/api/custom-rules', { headers: { Authorization: 'Bearer ' + TOKEN() } });
      const rules = await r.json();
      if (count) count.textContent = `(${rules.length})`;
      if (!rules.length) {
        list.innerHTML = '<p class="text-xs text-slate-400">No custom rules yet.</p>';
        return;
      }
      const SEV_COLOR = {Critical:'#e11d48',High:'#f97316',Medium:'#eab308',Low:'#3b82f6',Info:'#94a3b8'};
      list.innerHTML = rules.map(rule => `
        <div style="border:1px solid #e2e8f0;border-left:3px solid ${SEV_COLOR[rule.severity]||'#94a3b8'};border-radius:7px;padding:10px 12px;background:white;">
          <div style="display:flex;align-items:center;gap:6px;margin-bottom:4px;">
            <span style="font-size:13px;font-weight:600;color:#0f172a;flex:1;">${esc(rule.title)}</span>
            <span style="font-size:10px;padding:1px 7px;border-radius:99px;background:${SEV_COLOR[rule.severity]}22;color:${SEV_COLOR[rule.severity]};font-weight:700;">${esc(rule.severity)}</span>
            <button onclick="deleteCustomRule(${rule.id})" style="background:none;border:none;cursor:pointer;color:#94a3b8;font-size:14px;" title="Delete">✕</button>
          </div>
          ${rule.description ? `<div style="font-size:11px;color:#64748b;margin-bottom:4px;">${esc(rule.description.slice(0,80))}${rule.description.length>80?'…':''}</div>` : ''}
          <div style="font-size:10px;color:#94a3b8;">${esc(rule.category)} · ${rule.applies_to.length ? rule.applies_to.join(', ') : 'all components'} · ${rule.mitigations.length} mitigation(s)</div>
        </div>
      `).join('');
    } catch(e) { list.innerHTML = `<p class="text-xs text-red-400">Failed to load: ${esc(e.message)}</p>`; }
  }

  window.deleteCustomRule = async function(id) {
    if (!confirm('Delete this rule?')) return;
    await fetch(`/api/custom-rules/${id}`, { method: 'DELETE', headers: { Authorization: 'Bearer ' + TOKEN() } });
    await loadCustomRules();
    toast && toast('Rule deleted', 'success');
  };

  // Wire up on tab switch
  document.querySelectorAll('.tab-btn[data-tab="rules"]').forEach(btn => {
    btn.addEventListener('click', () => setTimeout(initCustomRulesTab, 100));
  });


})();
