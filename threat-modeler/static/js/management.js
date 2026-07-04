/* Management view: feature rollups, OWASP coverage, drill into TMs (read-only). */
(async function () {
  'use strict';

  const me = await Auth.requireRole(['management', 'admin']);
  if (!me) return;
  const esc = UI.escapeHtml;

  let allFeatures = [];
  let allTMs = [];
  let allUsers = [];
  let overview = [];

  // OWASP top 10 (2021) reference labels
  const OWASP_2021 = {
    "A01:2021": "Broken Access Control",
    "A02:2021": "Cryptographic Failures",
    "A03:2021": "Injection",
    "A04:2021": "Insecure Design",
    "A05:2021": "Security Misconfiguration",
    "A06:2021": "Vulnerable and Outdated Components",
    "A07:2021": "Identification and Authentication Failures",
    "A08:2021": "Software and Data Integrity Failures",
    "A09:2021": "Security Logging and Monitoring Failures",
    "A10:2021": "Server-Side Request Forgery",
  };

  function fmtDuration(seconds) {
    if (seconds === null || seconds === undefined) return '—';
    if (seconds < 60) return `${seconds}s`;
    if (seconds < 3600) return `${Math.round(seconds/60)}m`;
    if (seconds < 86400) return `${Math.round(seconds/3600)}h`;
    return `${Math.round(seconds/86400)}d`;
  }

  // Tab switching
  document.querySelectorAll('.tab').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tab').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      document.querySelectorAll('.tab-panel').forEach(p => p.classList.add('hidden'));
      document.getElementById('tab-' + btn.dataset.tab).classList.remove('hidden');
    });
  });

  // Honor ?tab= URL param
  const urlTab = new URLSearchParams(window.location.search).get('tab');
  if (urlTab) {
    const btn = document.querySelector(`.tab[data-tab="${urlTab}"]`);
    if (btn) btn.click();
  }

  async function loadAll() {
    const [overviewR, tmsR, featuresR] = await Promise.all([
      Auth.fetch('/api/management/overview'),
      Auth.fetch('/api/threat-models'),
      Auth.fetch('/api/features'),
    ]);
    if (!overviewR.ok || !tmsR.ok || !featuresR.ok) {
      UI.toast('Failed to load data', 'error');
      return;
    }
    overview = await overviewR.json();
    allTMs = await tmsR.json();
    allFeatures = await featuresR.json();
    try {
      const usersR = await Auth.fetch('/api/users');
      if (usersR.ok) allUsers = await usersR.json();
    } catch {}

    renderMetrics();
    renderFeatures();
    renderOwasp();
    renderTMs();
  }

  function renderMetrics() {
    let totalTMs = 0, totalThreats = 0, criticalCount = 0, mitigatedCount = 0;
    overview.forEach(f => {
      totalTMs += f.threat_model_count;
      totalThreats += f.total_threats;
      criticalCount += f.by_severity.Critical || 0;
      mitigatedCount += f.by_status.mitigated || 0;
    });
    UI.animateCount(document.getElementById('m-features'), overview.length);
    UI.animateCount(document.getElementById('m-tms'), totalTMs);
    UI.animateCount(document.getElementById('m-threats'), totalThreats);
    UI.animateCount(document.getElementById('m-critical'), criticalCount);
    UI.animateCount(document.getElementById('m-mitigated'), mitigatedCount);
  }

  function renderFeatures() {
    const grid = document.getElementById('feature-grid');
    if (overview.length === 0) {
      grid.classList.add('hidden');
      document.getElementById('empty-state').classList.remove('hidden');
      return;
    }
    grid.classList.remove('hidden');
    document.getElementById('empty-state').classList.add('hidden');

    grid.innerHTML = overview.map((f, i) => `
      <div class="card card-hover cursor-pointer" data-feature-id="${f.feature_id}" style="padding: 1.25rem;">
        <div class="flex items-start justify-between mb-2">
          <div>
            <h3 style="font-size: 1rem; font-weight: 700; margin: 0 0 2px 0;">${esc(f.feature_name)}</h3>
            <div class="text-xs text-light">${esc(f.release_name)}</div>
          </div>
          <span class="status status-${f.feature_status === 'released' ? 'mitigated' : f.feature_status === 'cancelled' ? 'false_positive' : 'in_progress'}">${esc(f.feature_status)}</span>
        </div>

        <div class="flex justify-center my-3">
          <svg id="ring-${i}"></svg>
        </div>

        <div class="space-y-2 mb-3">
          ${['Critical','High','Medium','Low','Info'].map(sev => {
            const count = f.by_severity[sev] || 0;
            if (count === 0 && f.total_threats > 0) return '';
            const pct = f.total_threats > 0 ? (count / f.total_threats * 100) : 0;
            const colorVar = sev === 'Critical' ? '--c-critical' :
                             sev === 'High' ? '--c-high' :
                             sev === 'Medium' ? '--c-medium' :
                             sev === 'Low' ? '--c-low' : '--c-info';
            return `
              <div class="flex items-center gap-2 text-xs">
                <span class="font-medium" style="width: 60px;">${sev}</span>
                <div class="progress-bar flex-1" style="height: 6px;">
                  <div class="progress-bar-fill" style="background: var(${colorVar}); width: ${pct}%;"></div>
                </div>
                <span class="text-light tabular-nums" style="width: 24px; text-align: right;">${count}</span>
              </div>
            `;
          }).join('')}
        </div>

        ${f.top_critical_titles.length > 0 ? `
          <div class="pt-3" style="border-top: 1px solid var(--c-border);">
            <div class="text-xs font-semibold text-light mb-1" style="text-transform: uppercase; letter-spacing: 0.05em;">⚠ Top critical</div>
            <ul style="margin: 0; padding: 0; list-style: none;">
              ${f.top_critical_titles.slice(0, 3).map(t => `<li class="text-xs" style="overflow: hidden; text-overflow: ellipsis; white-space: nowrap; padding: 1px 0;">• ${esc(t)}</li>`).join('')}
            </ul>
          </div>
        ` : ''}

        <div class="flex justify-between text-xs pt-3 mt-3" style="border-top: 1px solid var(--c-border);">
          <div class="text-center flex-1">
            <div class="font-bold" style="color: var(--c-critical);">${f.by_status.open || 0}</div>
            <div class="text-light">Open</div>
          </div>
          <div class="text-center flex-1">
            <div class="font-bold" style="color: var(--c-high);">${f.by_status.in_progress || 0}</div>
            <div class="text-light">In progress</div>
          </div>
          <div class="text-center flex-1">
            <div class="font-bold" style="color: var(--c-success);">${f.by_status.mitigated || 0}</div>
            <div class="text-light">Mitigated</div>
          </div>
        </div>

        ${f.avg_time_to_closure_seconds !== null && f.avg_time_to_closure_seconds !== undefined ? `
          <div class="text-xs text-center mt-2 text-light">
            ⏱ Avg time-to-closure: <strong style="color: var(--c-text);">${fmtDuration(f.avg_time_to_closure_seconds)}</strong>
            <span class="text-light"> · ${f.closures_count} closure${f.closures_count !== 1 ? 's' : ''}</span>
          </div>
        ` : ''}

        <div class="text-xs text-center mt-3 pt-3" style="border-top: 1px solid var(--c-border); color: var(--c-brand); font-weight: 500;">
          ${f.threat_model_count} threat model${f.threat_model_count !== 1 ? 's' : ''} → click to drill in
        </div>
      </div>
    `).join('');

    setTimeout(() => {
      overview.forEach((f, i) => {
        const ring = document.getElementById('ring-' + i);
        if (ring) UI.renderRingChart(ring, f.by_severity, f.total_threats, { size: 140 });
      });
    }, 50);

    document.querySelectorAll('[data-feature-id]').forEach(el => {
      el.addEventListener('click', () => {
        const fid = parseInt(el.dataset.featureId);
        // Switch to All Threat Models tab filtered to this feature
        document.querySelectorAll('.tab').forEach(b => b.classList.remove('active'));
        const threatsTab = document.querySelector('[data-tab="threats"]');
        threatsTab.classList.add('active');
        document.querySelectorAll('.tab-panel').forEach(p => p.classList.add('hidden'));
        document.getElementById('tab-threats').classList.remove('hidden');
        renderTMs(fid);
      });
    });
  }

  function renderOwasp() {
    const grid = document.getElementById('owasp-grid');
    // Aggregate across all features
    const aggregate = {};
    let totalOwasp = 0;
    overview.forEach(f => {
      Object.entries(f.by_owasp || {}).forEach(([cat, n]) => {
        aggregate[cat] = (aggregate[cat] || 0) + n;
        totalOwasp += n;
      });
    });

    if (totalOwasp === 0) {
      grid.innerHTML = `
        <div class="card text-center" style="padding: 3rem; grid-column: 1 / -1;">
          <p class="text-sm text-light">No OWASP-mapped threats yet. Run analysis on threat models to populate this view.</p>
        </div>`;
      return;
    }

    grid.innerHTML = Object.entries(OWASP_2021).map(([code, title]) => {
      const label = `${code} — ${title}`;
      const count = aggregate[label] || 0;
      const pct = totalOwasp > 0 ? (count / totalOwasp * 100).toFixed(1) : 0;
      const sev = count > 10 ? 'critical' : count > 3 ? 'high' : count > 0 ? 'medium' : 'none';
      const colorVar = sev === 'critical' ? '--c-critical' :
                       sev === 'high' ? '--c-high' :
                       sev === 'medium' ? '--c-medium' : '--c-info';
      const bgGradient = sev === 'critical' ? 'linear-gradient(135deg, #fef2f2, #fff)' :
                         sev === 'high' ? 'linear-gradient(135deg, #fff7ed, #fff)' :
                         sev === 'medium' ? 'linear-gradient(135deg, #fefce8, #fff)' :
                         'linear-gradient(135deg, #f8fafc, #fff)';
      return `
        <div class="card" style="padding: 1.25rem; background: ${bgGradient};">
          <div class="flex justify-between items-start mb-3">
            <div>
              <div class="text-xs font-bold text-light" style="text-transform: uppercase; letter-spacing: 0.05em;">${code}</div>
              <div style="font-weight: 700; font-size: 0.95rem; margin-top: 2px;">${esc(title)}</div>
            </div>
            <div class="text-right">
              <div style="font-size: 2rem; font-weight: 800; line-height: 1; color: ${count > 0 ? `var(${colorVar})` : 'var(--c-text-light)'}; font-variant-numeric: tabular-nums;">${count}</div>
              <div class="text-xs text-light">${pct}%</div>
            </div>
          </div>
          <div class="progress-bar" style="height: 6px;">
            <div class="progress-bar-fill" style="background: var(${colorVar}); width: ${pct}%;"></div>
          </div>
          <a href="https://owasp.org/Top10/${code.replace(':', '_')}-${title.replace(/ /g, '_')}/" target="_blank" rel="noopener" class="text-xs mt-2" style="color: var(--c-brand); text-decoration: none; display: inline-block;">Learn more →</a>
        </div>
      `;
    }).join('');
  }

  function renderTMs(filterFeatureId) {
    const tbody = document.getElementById('all-tms-tbody');
    const filtered = filterFeatureId ? allTMs.filter(t => t.feature_id === filterFeatureId) : allTMs;
    if (filtered.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" class="text-center text-light" style="padding: 2rem;">No threat models</td></tr>';
      return;
    }
    const featureMap = Object.fromEntries(allFeatures.map(f => [f.id, f]));
    const userMap = Object.fromEntries(allUsers.map(u => [u.id, u]));

    tbody.innerHTML = filtered.map(t => {
      const feature = featureMap[t.feature_id];
      const owner = userMap[t.owner_id];
      return `
        <tr class="cursor-pointer" data-tm-id="${t.id}">
          <td><strong>${esc(t.name)}</strong></td>
          <td>${esc(feature ? feature.name : '#' + t.feature_id)}</td>
          <td>${esc(owner ? owner.email : '#' + t.owner_id)}</td>
          <td class="text-light text-xs">${(t.updated_at || '').slice(0, 10)}</td>
          <td class="text-right" style="color: var(--c-brand); font-weight: 500;">View →</td>
        </tr>
      `;
    }).join('');

    document.querySelectorAll('[data-tm-id]').forEach(el => {
      el.addEventListener('click', () => openDetail(parseInt(el.dataset.tmId)));
    });
  }

  // ============================================================================
  //  Detail modal — same rich view as user dashboard, but read-only
  // ============================================================================
  let currentTM = null;
  let filter = { severity: null, status: null, search: '' };

  async function openDetail(tmId) {
    UI.showModal('modal-tm-detail');
    document.getElementById('detail-title').textContent = 'Loading...';
    document.getElementById('detail-subtitle').textContent = '';
    document.getElementById('detail-body').innerHTML = `
      <div class="text-center" style="padding: 4rem 0;">
        <div class="dots-loader" style="font-size: 2rem; color: var(--c-brand);"><span></span><span></span><span></span></div>
        <div class="text-sm text-light mt-3">Loading threat model...</div>
      </div>`;

    const r = await Auth.fetch('/api/threat-models/' + tmId);
    if (!r.ok) {
      document.getElementById('detail-body').innerHTML = '<p style="color: var(--c-critical);">Failed to load</p>';
      return;
    }
    currentTM = await r.json();
    filter = { severity: null, status: null, search: '' };
    renderDetail();
  }

  function renderDetail() {
    const tm = currentTM;
    const featureName = (allFeatures.find(f => f.id === tm.feature_id) || {}).name || `#${tm.feature_id}`;
    const owner = allUsers.find(u => u.id === tm.owner_id);
    document.getElementById('detail-title').textContent = tm.name;
    document.getElementById('detail-subtitle').textContent =
      `${featureName} · Owner: ${owner ? owner.email : '#' + tm.owner_id} · Updated ${(tm.updated_at || '').slice(0, 10)}`;

    const analysis = tm.analysis;
    if (!analysis) {
      document.getElementById('detail-body').innerHTML = `
        <p class="text-sm text-light mb-4">${esc(tm.description || 'No description')}</p>
        <div class="card text-center" style="padding: 2rem;">
          <p class="text-sm text-light">No analysis run yet on this threat model.</p>
        </div>`;
      return;
    }

    const sev = analysis.summary.by_severity || {};
    const total = analysis.summary.total || 0;

    const body = `
      <p class="text-sm text-light mb-6">${esc(tm.description || 'No description')}</p>

      <div class="grid grid-cols-2 md:grid-cols-3 gap-4 mb-6">
        <div class="card flex items-center justify-center" style="padding: 1rem; background: linear-gradient(135deg, #fafbff, #eef2ff);">
          <svg id="detail-ring"></svg>
        </div>
        <div class="grid grid-cols-2 md:grid-cols-3 gap-2" style="grid-column: span 2; align-content: center;">
          ${['Critical','High','Medium','Low','Info'].map(s => `
            <button data-filter-sev="${s}" class="card cursor-pointer" style="padding: 0.75rem; text-align: center; ${filter.severity === s ? 'border-color: var(--c-brand); box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.15);' : ''}">
              <div class="text-xs font-semibold text-light" style="text-transform: uppercase; letter-spacing: 0.05em;">${s}</div>
              <div style="font-size: 1.75rem; font-weight: 800; line-height: 1.1; margin-top: 0.25rem; font-variant-numeric: tabular-nums; color: ${s==='Critical'?'var(--c-critical)':s==='High'?'var(--c-high)':s==='Medium'?'var(--c-medium)':s==='Low'?'var(--c-low)':'var(--c-info)'};">${sev[s] || 0}</div>
            </button>
          `).join('')}
        </div>
      </div>

      <div class="tabs" style="margin-bottom: 1rem;">
        <button data-tab="threats" class="tab active">Threats <span class="text-light text-xs">(${total})</span></button>
        <button data-tab="dfd" class="tab">Data Flow Diagram</button>
        <button data-tab="system" class="tab">System Components</button>
      </div>

      <div id="detail-tab-threats" class="detail-tab-panel">
        <div class="flex justify-between items-center mb-4 gap-3" style="flex-wrap: wrap;">
          <div class="flex gap-2 items-center" style="flex-wrap: wrap;">
            <input id="threat-search" type="text" placeholder="Search threats..." class="input" style="font-size: 0.875rem; padding: 0.4rem 0.75rem; width: 12rem;" />
            <select id="threat-status-filter" class="select" style="font-size: 0.875rem; padding: 0.4rem 0.75rem; width: auto;">
              <option value="">All statuses</option>
              <option value="open">Open</option>
              <option value="in_progress">In progress</option>
              <option value="mitigated">Mitigated</option>
              <option value="accepted_risk">Accepted</option>
              <option value="false_positive">False positive</option>
            </select>
            ${filter.severity ? `<button id="clear-sev-filter" class="btn btn-sm" style="background: var(--c-brand); color: white;">Severity: ${filter.severity} ×</button>` : ''}
          </div>
          <div class="flex gap-2">
            <button data-download="markdown" data-tm-id="${tm.id}" class="btn btn-sm btn-ghost">↓ MD</button>
            <button data-download="html" data-tm-id="${tm.id}" class="btn btn-sm btn-ghost">↓ HTML</button>
            <button data-download="pdf" data-tm-id="${tm.id}" class="btn btn-sm btn-ghost">↓ PDF</button>
          </div>
        </div>
        <div id="threat-list"></div>
      </div>

      <div id="detail-tab-dfd" class="detail-tab-panel hidden">
        <div class="card mb-4" style="padding: 1rem;">
          <p class="text-xs text-light mb-2">🔒 Solid lines = encrypted · ⚠ Dashed red = unencrypted/cross-boundary</p>
          <div id="dfd-container" style="background: white; border-radius: 6px; padding: 0.75rem; overflow: auto; max-height: 70vh;">
            <div class="text-center" style="padding: 3rem 0;">
              <div class="dots-loader" style="color: var(--c-brand);"><span></span><span></span><span></span></div>
              <div class="text-sm text-light mt-3">Generating diagram...</div>
            </div>
          </div>
        </div>
        ${analysis.system && analysis.system.trust_boundaries && analysis.system.trust_boundaries.length > 0 ? `
          <div class="card" style="padding: 1rem; background: linear-gradient(135deg, #fef3c7, #fffbeb); border-color: #fde68a;">
            <h4 style="font-size: 0.875rem; font-weight: 700; color: #78350f; margin: 0 0 0.5rem 0;">🛡 Trust Boundaries</h4>
            <ul style="margin: 0; padding: 0; list-style: none;">
              ${analysis.system.trust_boundaries.map(b => {
                const components = (b.contains || []).map(cid => {
                  const c = (analysis.system.components || []).find(c => c.id === cid);
                  return c ? c.name : cid;
                });
                return `<li class="text-sm" style="color: #78350f; padding: 2px 0;"><strong>${esc(b.name)}</strong> — contains: ${components.map(esc).join(', ') || '(none)'}</li>`;
              }).join('')}
            </ul>
          </div>
        ` : ''}
      </div>

      <div id="detail-tab-system" class="detail-tab-panel hidden">
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <h4 class="text-xs font-semibold text-light mb-2" style="text-transform: uppercase; letter-spacing: 0.05em;">Components (${(tm.system && tm.system.components || []).length})</h4>
            <div class="flex-col gap-1">
              ${(tm.system && tm.system.components || []).map(c => `
                <div class="card" style="padding: 0.6rem 0.75rem;">
                  <div style="font-weight: 600; font-size: 0.875rem;">${esc(c.name)}</div>
                  <div class="text-xs text-light">${esc(c.type || 'component')}</div>
                </div>
              `).join('')}
            </div>
          </div>
          <div>
            <h4 class="text-xs font-semibold text-light mb-2" style="text-transform: uppercase; letter-spacing: 0.05em;">Data Flows (${(tm.system && tm.system.data_flows || []).length})</h4>
            <div class="flex-col gap-1">
              ${(tm.system && tm.system.data_flows || []).map(f => {
                const fromName = (tm.system.components.find(c => c.id === f.from) || {}).name || f.from;
                const toName = (tm.system.components.find(c => c.id === f.to) || {}).name || f.to;
                return `
                  <div class="card" style="padding: 0.6rem 0.75rem;">
                    <div style="font-size: 0.875rem;">${esc(fromName)} <span style="color: var(--c-brand);">→</span> ${esc(toName)} ${f.encrypted ? '🔒' : '<span style="color: var(--c-critical);">⚠</span>'}</div>
                    <div class="text-xs text-light">${esc(f.data || '')} · auth: ${esc(f.auth || 'none')}</div>
                  </div>
                `;
              }).join('')}
            </div>
          </div>
        </div>
      </div>
    `;

    document.getElementById('detail-body').innerHTML = body;

    const ring = document.getElementById('detail-ring');
    if (ring) UI.renderRingChart(ring, sev, total, { size: 160 });

    renderThreats();
    wireDetailActions();
  }

  function getFilteredThreats() {
    if (!currentTM || !currentTM.analysis) return [];
    let threats = currentTM.analysis.threats || [];
    if (filter.severity) threats = threats.filter(t => t.severity === filter.severity);
    if (filter.status) {
      threats = threats.filter(t => {
        const s = (currentTM.threat_statuses[t.id] && currentTM.threat_statuses[t.id].status) || 'open';
        return s === filter.status;
      });
    }
    if (filter.search) {
      const q = filter.search.toLowerCase();
      threats = threats.filter(t =>
        (t.title || '').toLowerCase().includes(q) ||
        (t.description || '').toLowerCase().includes(q) ||
        (t.category || '').toLowerCase().includes(q)
      );
    }
    return threats;
  }

  function renderThreats() {
    const list = document.getElementById('threat-list');
    if (!list) return;
    const threats = getFilteredThreats();
    const total = currentTM.analysis.threats.length;
    const statuses = currentTM.threat_statuses || {};

    if (threats.length === 0) {
      list.innerHTML = '<div class="text-center text-light text-sm" style="padding: 2rem;">No threats match filters</div>';
      return;
    }

    list.innerHTML = `
      <div class="text-xs text-light mb-2">Showing ${threats.length} of ${total} threats</div>
      <div class="flex-col gap-2">
        ${threats.slice(0, 100).map((t, i) => {
          const status = (statuses[t.id] && statuses[t.id].status) || 'open';
          const cwe = t.cwe || {};
          const cvss31 = t.cvss31 || {};
          const owasp = (t.references || []).find(r => /A0\d/.test(r.label || ''));
          const dread = t.dread || {};

          return `
            <div data-threat-row data-threat-id="${esc(t.id)}" class="threat-row status-${status}" style="animation: fadeInUp 0.3s ease-out ${Math.min(i, 30)*15}ms backwards">
              <div class="threat-header">
                <div class="sev sev-${t.severity || 'Medium'}">${t.severity || 'Medium'}</div>
                <div style="flex: 1; min-width: 0;">
                  <div class="threat-title">${esc(t.title || 'Untitled')}</div>
                  <div class="threat-meta">
                    <span class="threat-meta-tag">${esc(t.methodology || '')}</span>
                    <span>${esc(t.category || '')}</span>
                    ${cwe.id ? `<span class="threat-meta-tag threat-meta-tag-cwe">${esc(cwe.id)}</span>` : ''}
                    ${owasp ? `<span class="threat-meta-tag threat-meta-tag-owasp">${esc(owasp.label)}</span>` : ''}
                    ${cvss31.score !== undefined ? `<span class="threat-meta-tag threat-meta-tag-cvss">CVSS ${cvss31.score}</span>` : ''}
                  </div>
                </div>
                <div class="flex items-center gap-2">
                  <span class="status status-${status}">${status.replace('_', ' ')}</span>
                  <svg class="expand-icon" style="width: 16px; height: 16px; color: var(--c-text-light); transition: transform 0.2s ease;" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M19 9l-7 7-7-7"/></svg>
                </div>
              </div>
              <div class="threat-detail hidden">
                <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                  <div class="detail-section" style="margin: 0;">
                    <div class="detail-section-title">Description</div>
                    <p class="text-sm">${esc(t.description || '—')}</p>
                  </div>
                  <div class="detail-section" style="margin: 0;">
                    <div class="detail-section-title">Location</div>
                    <p class="text-sm">${esc(t.location || '—')}</p>
                  </div>
                </div>

                ${t.attack_scenario && t.attack_scenario.length > 0 ? `
                  <div class="detail-section">
                    <div class="detail-section-title">⚠ Attack Scenario</div>
                    <div class="flex-col gap-1">
                      ${t.attack_scenario.map((s, idx) => `
                        <div class="attack-step">
                          <div class="attack-step-num">${idx+1}</div>
                          <div>${esc(s)}</div>
                        </div>
                      `).join('')}
                    </div>
                  </div>
                ` : ''}

                ${t.specific_mitigations && t.specific_mitigations.length > 0 ? `
                  <div class="detail-section">
                    <div class="detail-section-title" style="color: var(--c-success);">✓ Mitigations</div>
                    ${t.specific_mitigations.map(m => `
                      <div class="mitigation-card">
                        <div class="mitigation-action">${esc(m.action || m)}</div>
                        ${m.detail ? `<div class="mitigation-detail">${esc(m.detail)}</div>` : ''}
                      </div>
                    `).join('')}
                  </div>
                ` : (t.mitigations && t.mitigations.length > 0 ? `
                  <div class="detail-section">
                    <div class="detail-section-title" style="color: var(--c-success);">✓ Mitigations</div>
                    <ul style="margin: 0; padding-left: 1rem; font-size: 0.875rem;">
                      ${t.mitigations.map(m => `<li>${esc(m)}</li>`).join('')}
                    </ul>
                  </div>
                ` : '')}

                <div class="grid grid-cols-1 md:grid-cols-3 gap-3 mb-4">
                  ${cwe.id ? `
                    <div class="metric-box metric-box-cwe">
                      <div class="metric-box-label">CWE</div>
                      <div class="metric-box-value">${esc(cwe.id)}: ${esc(cwe.name || '')}</div>
                      ${cwe.url ? `<a href="${esc(cwe.url)}" target="_blank" class="metric-box-detail" style="color: #7c3aed; text-decoration: none;">View on cwe.mitre.org →</a>` : ''}
                    </div>
                  ` : ''}
                  ${cvss31.score !== undefined ? `
                    <div class="metric-box metric-box-cvss">
                      <div class="metric-box-label">CVSS 3.1</div>
                      <div class="metric-box-value">${cvss31.score} · ${esc(cvss31.severity || '')}</div>
                      <div class="metric-box-detail">${esc(cvss31.vector || '')}</div>
                    </div>
                  ` : ''}
                  ${dread.total !== undefined ? `
                    <div class="metric-box metric-box-dread">
                      <div class="metric-box-label">DREAD</div>
                      <div class="metric-box-value">${dread.total}/50</div>
                      <div class="metric-box-detail" style="font-family: inherit; word-break: normal;">D${dread.D_damage} R${dread.R_reproducibility} E${dread.E_exploitability} A${dread.A_affected_users} D${dread.D_discoverability}</div>
                    </div>
                  ` : ''}
                </div>

                ${t.references && t.references.length > 0 ? `
                  <div class="detail-section">
                    <div class="detail-section-title">References</div>
                    <div class="flex gap-2" style="flex-wrap: wrap;">
                      ${t.references.map(r => `<a href="${esc(r.url || '#')}" target="_blank" class="ref-badge">${esc(r.label || r.url || 'Ref')}</a>`).join('')}
                    </div>
                  </div>
                ` : ''}
              </div>
            </div>
          `;
        }).join('')}
      </div>
      ${threats.length > 100 ? `<p class="text-xs text-center text-light mt-3">Showing first 100 of ${threats.length}.</p>` : ''}
    `;

    list.querySelectorAll('.threat-header').forEach(h => {
      h.addEventListener('click', (e) => {
        const detail = h.parentElement.querySelector('.threat-detail');
        const icon = h.querySelector('.expand-icon');
        detail.classList.toggle('hidden');
        if (icon) icon.style.transform = detail.classList.contains('hidden') ? '' : 'rotate(180deg)';
      });
    });
  }

  function wireDetailActions() {
    document.querySelectorAll('#detail-body .tab').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('#detail-body .tab').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        document.querySelectorAll('.detail-tab-panel').forEach(p => p.classList.add('hidden'));
        document.getElementById('detail-tab-' + btn.dataset.tab).classList.remove('hidden');
        if (btn.dataset.tab === 'dfd') loadDfd();
      });
    });

    document.querySelectorAll('[data-filter-sev]').forEach(btn => {
      btn.addEventListener('click', () => {
        const sev = btn.dataset.filterSev;
        filter.severity = filter.severity === sev ? null : sev;
        renderDetail();
      });
    });

    const search = document.getElementById('threat-search');
    if (search) search.addEventListener('input', (e) => {
      filter.search = e.target.value;
      renderThreats();
    });
    const statusFilter = document.getElementById('threat-status-filter');
    if (statusFilter) statusFilter.addEventListener('change', (e) => {
      filter.status = e.target.value || null;
      renderThreats();
    });

    const clearSev = document.getElementById('clear-sev-filter');
    if (clearSev) clearSev.addEventListener('click', () => {
      filter.severity = null;
      renderDetail();
    });

    document.querySelectorAll('[data-download]').forEach(btn => {
      btn.addEventListener('click', async () => {
        const fmt = btn.dataset.download;
        const tmId = btn.dataset.tmId;
        const ext = fmt === 'markdown' ? 'md' : fmt === 'pdf' ? 'pdf' : 'html';
        const original = btn.innerHTML;
        btn.innerHTML = '<span class="dots-loader"><span></span><span></span><span></span></span>';
        try {
          await UI.downloadFile(`/api/threat-models/${tmId}/report/${fmt}`, `threat_model_${tmId}.${ext}`);
          UI.toast(`${fmt.toUpperCase()} downloaded`, 'success', 1500);
        } catch (e) { /* shown */ }
        btn.innerHTML = original;
      });
    });
  }

  async function loadDfd() {
    const container = document.getElementById('dfd-container');
    if (!container || container.dataset.loaded === '1') return;
    container.dataset.loaded = '1';
    container.innerHTML = '';
    if (!window.DfdEditor) {
      container.innerHTML = '<p class="text-sm" style="color: var(--c-critical);">DFD editor failed to load.</p>';
      return;
    }
    window.DfdEditor.mount(container, currentTM.system || {}, {
      readOnly: true,   // management is read-only
      sourceText: '',
      onChange: function () {},
    });
  }

  document.getElementById('btn-refresh').addEventListener('click', loadAll);
  loadAll();
})();
