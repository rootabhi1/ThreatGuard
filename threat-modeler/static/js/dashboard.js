/* User dashboard — list, create, detail with DFD + threat metadata. */
(async function () {
  'use strict';

  const me = await Auth.requireRole(['user', 'admin']);
  if (!me) return;

  const esc = UI.escapeHtml;
  let allTMs = [];
  let allFeatures = [];

  // =========================================================================
  //  Load
  // =========================================================================
  async function loadAll() {
    const [tmResp, featResp] = await Promise.all([
      Auth.fetch('/api/threat-models'),
      Auth.fetch('/api/features'),
    ]);
    if (!tmResp.ok) {
      UI.toast('Failed to load threat models', 'error');
      return;
    }
    allTMs = await tmResp.json();
    allFeatures = featResp.ok ? await featResp.json() : [];
    renderStats();
    renderList();
  }

  function renderStats() {
    UI.animateCount(document.getElementById('stat-total'), allTMs.length);
    UI.animateCount(document.getElementById('stat-threats'), 0);
    UI.animateCount(document.getElementById('stat-open'), 0);
    UI.animateCount(document.getElementById('stat-mitigated'), 0);

    // Aggregate from full TM details (background)
    (async () => {
      let threats = 0, open = 0, mitigated = 0;
      const results = await Promise.all(
        allTMs.map(t => Auth.fetch('/api/threat-models/' + t.id).then(r => r.ok ? r.json() : null).catch(() => null))
      );
      for (const tm of results) {
        if (!tm || !tm.analysis) continue;
        threats += tm.analysis.summary.total || 0;
        const statuses = tm.threat_statuses || {};
        for (const t of tm.analysis.threats || []) {
          const s = (statuses[t.id] && statuses[t.id].status) || 'open';
          if (s === 'open') open++;
          else if (s === 'mitigated') mitigated++;
        }
      }
      UI.animateCount(document.getElementById('stat-threats'), threats);
      UI.animateCount(document.getElementById('stat-open'), open);
      UI.animateCount(document.getElementById('stat-mitigated'), mitigated);
    })();
  }

  function renderList() {
    const container = document.getElementById('tm-list');
    const empty = document.getElementById('empty-state');
    if (allTMs.length === 0) {
      container.classList.add('hidden');
      empty.classList.remove('hidden');
      return;
    }
    container.classList.remove('hidden');
    empty.classList.add('hidden');

    const featureMap = {};
    allFeatures.forEach(f => featureMap[f.id] = f);

    container.innerHTML = allTMs.map(tm => {
      const feature = featureMap[tm.feature_id];
      const featureName = feature ? feature.name : `#${tm.feature_id}`;
      const updated = (tm.updated_at || '').slice(0, 10);
      const methodologies = (tm.methodologies || []).slice(0, 4).map(m =>
        `<span class="threat-meta-tag" style="text-transform: uppercase; font-size: 0.625rem;">${m}</span>`
      ).join(' ');
      const compCount = (tm.system && tm.system.components && tm.system.components.length) || 0;

      return `
        <div class="card card-interactive card-accent p-4" data-tm-id="${tm.id}">
          <div class="flex items-center justify-between mb-2">
            <h3 class="font-bold truncate" style="font-size: 1rem;">${esc(tm.name)}</h3>
          </div>
          <div class="text-xs text-light flex items-center gap-2 mb-3">
            <svg width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M5 8h14M5 12h14M5 16h14"/></svg>
            <span>${esc(featureName)}</span>
          </div>
          <p class="text-sm text-dim line-clamp-2 mb-3" style="min-height: 2.5em;">${esc(tm.description || 'No description')}</p>
          <div class="flex gap-1 mb-3">${methodologies}</div>
          <div class="flex items-center justify-between" style="padding-top: 0.75rem; border-top: 1px solid var(--c-surface-2); font-size: 0.75rem; color: var(--c-text-light);">
            <span class="flex items-center gap-1">
              <svg width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><polyline points="12 7 12 12 15 14"/></svg>
              ${updated}
            </span>
            <span class="font-semibold" style="color: var(--c-brand);">${compCount} components →</span>
          </div>
        </div>
      `;
    }).join('');

    container.querySelectorAll('[data-tm-id]').forEach(el => {
      el.addEventListener('click', () => openDetail(parseInt(el.dataset.tmId)));
    });
  }

  // =========================================================================
  //  New TM modal
  // =========================================================================
  function populateFeatureSelect() {
    const sel = document.getElementById('select-feature');
    const help = document.getElementById('feature-help');
    if (allFeatures.length === 0) {
      sel.innerHTML = '<option value="">No features available</option>';
      sel.disabled = true;
      help.textContent = 'No features yet. Ask an admin to grant you access.';
      help.classList.add('field-help-error');
      return;
    }
    sel.disabled = false;
    sel.innerHTML = '<option value="">Select a feature...</option>' +
      allFeatures.map(f => `<option value="${f.id}">${esc(f.name)}</option>`).join('');
    help.textContent = `${allFeatures.length} feature(s) you have access to.`;
    help.classList.remove('field-help-error');
  }

  async function updateLlmStatusBadge() {
    const badge = document.getElementById('llm-status-badge');
    const cb = document.getElementById('use-llm');
    if (!badge) return;
    try {
      const r = await fetch('/api/health');
      const data = await r.json();
      if (data.llm_configured) {
        badge.textContent = 'Available';
        badge.className = 'role-badge';
        badge.style.cssText = 'background: linear-gradient(135deg, #d1fae5, #a7f3d0); color: #065f46; font-size: 0.625rem;';
      } else {
        badge.textContent = 'Not configured';
        badge.className = 'role-badge';
        badge.style.cssText = 'background: linear-gradient(135deg, #fef3c7, #fde68a); color: #92400e; font-size: 0.625rem;';
        cb.disabled = true;
        cb.checked = false;
      }
    } catch { badge.textContent = 'Unknown'; }
  }

  function openNewModal() {
    const form = document.getElementById('form-new-tm');
    if (form) form.reset();
    const stride = document.querySelector('input[name="methodology"][value="stride"]');
    if (stride) stride.checked = true;
    document.getElementById('new-tm-error').classList.add('hidden');
    populateFeatureSelect();
    updateLlmStatusBadge();
    UI.showModal('modal-new-tm');
  }

  document.getElementById('btn-new-tm').addEventListener('click', openNewModal);
  const btnNewEmpty = document.getElementById('btn-new-tm-empty');
  if (btnNewEmpty) btnNewEmpty.addEventListener('click', openNewModal);

  document.getElementById('form-new-tm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const errBox = document.getElementById('new-tm-error');
    const submitBtn = document.getElementById('submit-new-tm');
    const submitLabel = submitBtn.querySelector('.submit-label');
    errBox.classList.add('hidden');
    submitBtn.disabled = true;

    const setProgress = (text) => {
      submitLabel.innerHTML = `<span class="dots-loader"><span></span><span></span><span></span></span> ${text}`;
    };

    try {
      const fd = new FormData(e.target);
      const featureId = parseInt(fd.get('feature_id'));
      const methodologies = Array.from(document.querySelectorAll('input[name="methodology"]:checked')).map(cb => cb.value);
      if (methodologies.length === 0) throw new Error('Pick at least one methodology');
      const useLlm = document.getElementById('use-llm').checked;

      setProgress(useLlm ? 'Extracting components with AI...' : 'Extracting components...');
      const extractResp = await Auth.fetch('/api/extract-from-text', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: fd.get('system_text'), use_llm: useLlm }),
      });
      if (!extractResp.ok) throw new Error((await extractResp.json()).detail || 'Extraction failed');
      const system = await extractResp.json();
      if (!system.name) system.name = fd.get('name');
      // Stash the inference mode + source text for later display
      system._boundary_inference_mode = system.boundary_inference_mode || 'heuristic';
      system._source_text = fd.get('system_text');
      delete system.boundary_inference_mode;

      setProgress('Creating threat model...');
      const createResp = await Auth.fetch('/api/threat-models', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          feature_id: featureId,
          name: fd.get('name'),
          description: fd.get('description') || '',
          system,
          methodologies,
        }),
      });
      if (!createResp.ok) throw new Error((await createResp.json()).detail || 'Create failed');
      const tm = await createResp.json();

      setProgress(useLlm ? 'Running analysis (LLM, ~30s)...' : 'Running analysis...');
      const analyzeResp = await Auth.fetch(`/api/threat-models/${tm.id}/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ methodologies, use_llm: useLlm }),
      });
      if (!analyzeResp.ok) throw new Error((await analyzeResp.json()).detail || 'Analysis failed');
      const analysis = await analyzeResp.json();

      UI.hideModal('modal-new-tm');
      UI.toast(`Created "${tm.name}" — ${analysis.summary.total} threats identified`, 'success');
      await loadAll();
      openDetail(tm.id);
    } catch (err) {
      errBox.textContent = err.message;
      errBox.classList.remove('hidden');
    } finally {
      submitBtn.disabled = false;
      submitLabel.textContent = 'Create & analyze';
    }
  });

  // =========================================================================
  //  Detail modal
  // =========================================================================
  let currentTM = null;
  let filter = { severity: null, status: null, search: '' };

  async function openDetail(tmId) {
    UI.showModal('modal-tm-detail');
    document.getElementById('detail-title').textContent = 'Loading...';
    document.getElementById('detail-subtitle').textContent = '';
    document.getElementById('detail-body').innerHTML = `
      <div class="text-center" style="padding: 4rem 0;">
        <div class="dots-loader text-brand" style="font-size: 2rem;"><span></span><span></span><span></span></div>
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
    document.getElementById('detail-title').textContent = tm.name;
    document.getElementById('detail-subtitle').textContent = `${featureName} · Updated ${(tm.updated_at || '').slice(0, 10)}`;

    const analysis = tm.analysis;
    if (!analysis) {
      document.getElementById('detail-body').innerHTML = `
        <p class="text-sm text-dim mb-4">${esc(tm.description || 'No description')}</p>
        <div class="card p-6 text-center">
          <p class="text-sm text-dim mb-3">No analysis run yet on this threat model.</p>
          <button id="btn-run-analysis" class="btn btn-primary" data-tm-id="${tm.id}">Run analysis</button>
        </div>`;
      wireDetailActions();
      return;
    }

    const sev = analysis.summary.by_severity || {};
    const total = analysis.summary.total || 0;

    const body = `
      <p class="text-sm text-dim mb-6">${esc(tm.description || 'No description')}</p>

      <!-- Severity breakdown -->
      <div class="grid grid-cols-2 md:grid-cols-3 gap-4 mb-6">
        <div class="card p-4 flex items-center justify-center" style="background: linear-gradient(135deg, #fafbff, #eef2ff);">
          <svg id="detail-ring"></svg>
        </div>
        <div class="grid grid-cols-2 md:grid-cols-3 gap-2" style="grid-column: span 2; align-content: center;">
          ${['Critical','High','Medium','Low','Info'].map(s => `
            <button data-filter-sev="${s}" class="card p-3 text-center cursor-pointer ${filter.severity === s ? 'animate-glow' : ''}" style="${filter.severity === s ? 'border-color: var(--c-brand);' : ''}">
              <div class="text-xs font-semibold" style="text-transform: uppercase; letter-spacing: 0.05em; color: var(--c-text-light);">${s}</div>
              <div style="font-size: 1.75rem; font-weight: 800; font-variant-numeric: tabular-nums; line-height: 1.1; margin-top: 0.25rem; color: ${s==='Critical'?'var(--c-critical)':s==='High'?'var(--c-high)':s==='Medium'?'#ca8a04':s==='Low'?'var(--c-low)':'var(--c-info)'};">${sev[s] || 0}</div>
            </button>
          `).join('')}
        </div>
      </div>

      <!-- Tabs -->
      <div class="tabs">
        <button data-tab="threats" class="tab active">Threats <span class="tab-badge">${total}</span></button>
        <button data-tab="dfd" class="tab">Data Flow Diagram</button>
        <button data-tab="system" class="tab">System Components</button>
      </div>

      <!-- Threats panel -->
      <div id="tab-threats" class="tab-panel">
        <div class="flex items-center justify-between mb-4 gap-3" style="flex-wrap: wrap;">
          <div class="flex items-center gap-2" style="flex-wrap: wrap;">
            <input id="threat-search" type="text" placeholder="Search threats..." class="input" style="width: 200px;">
            <select id="threat-status-filter" class="select" style="width: auto;">
              <option value="">All statuses</option>
              <option value="open">Open</option>
              <option value="in_progress">In progress</option>
              <option value="mitigated">Mitigated</option>
              <option value="accepted_risk">Accepted</option>
              <option value="false_positive">False positive</option>
            </select>
            ${filter.severity ? `<button id="clear-sev-filter" class="btn btn-sm btn-secondary">Severity: ${filter.severity} ×</button>` : ''}
          </div>
          <div class="flex gap-2">
            <button data-download="markdown" data-tm-id="${tm.id}" class="btn btn-sm btn-secondary">↓ MD</button>
            <button data-download="html" data-tm-id="${tm.id}" class="btn btn-sm btn-secondary">↓ HTML</button>
            <button data-download="pdf" data-tm-id="${tm.id}" class="btn btn-sm btn-secondary">↓ PDF</button>
          </div>
        </div>
        <div id="threat-list" class="flex-col gap-2"></div>
      </div>

      <!-- DFD panel -->
      <div id="tab-dfd" class="tab-panel hidden">
        <div class="flex items-center justify-between mb-3 gap-2" style="flex-wrap: wrap;">
          <div class="text-xs text-light">🔒 Solid = encrypted · ⚠ Dashed red = unencrypted/cross-boundary · drag components, click to edit</div>
          <button id="btn-save-dfd" class="btn btn-sm btn-primary hidden">Save layout & changes</button>
        </div>
        <div id="dfd-container" class="dfd-container" style="height: 600px;">
          <div class="text-center" style="padding: 3rem 0;">
            <div class="spinner" style="margin: 0 auto;"></div>
            <div class="text-sm text-light mt-3">Loading editor...</div>
          </div>
        </div>
      </div>

      <!-- System panel -->
      <div id="tab-system" class="tab-panel hidden">
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <div class="text-xs font-bold text-light mb-2" style="text-transform: uppercase; letter-spacing: 0.08em;">Components (${(tm.system.components || []).length})</div>
            <div class="flex-col gap-1">
              ${(tm.system.components || []).map(c => `
                <div class="card p-3">
                  <div class="font-semibold text-sm">${esc(c.name)}</div>
                  <div class="text-xs text-light">${esc(c.type || 'component')}</div>
                </div>
              `).join('')}
            </div>
          </div>
          <div>
            <div class="text-xs font-bold text-light mb-2" style="text-transform: uppercase; letter-spacing: 0.08em;">Data Flows (${(tm.system.data_flows || []).length})</div>
            <div class="flex-col gap-1">
              ${(tm.system.data_flows || []).map(f => {
                const fromName = (tm.system.components.find(c => c.id === f.from) || {}).name || f.from;
                const toName = (tm.system.components.find(c => c.id === f.to) || {}).name || f.to;
                return `
                  <div class="card p-3">
                    <div class="text-sm font-semibold">
                      ${esc(fromName)} <span class="text-brand">→</span> ${esc(toName)}
                      ${f.encrypted ? '<span style="font-size:0.75rem;">🔒</span>' : '<span style="font-size:0.75rem; color: var(--c-critical);">⚠</span>'}
                    </div>
                    <div class="text-xs text-light">${esc(f.data || '')} · auth: ${esc(f.auth || 'none')}</div>
                  </div>
                `;
              }).join('')}
            </div>
          </div>
        </div>
      </div>

      <div class="mt-6 pt-4 flex justify-between items-center" style="border-top: 1px solid var(--c-border);">
        <div class="text-xs text-light">Created ${(tm.created_at || '').slice(0, 10)}</div>
        <div class="flex gap-2">
          <button id="btn-rerun" class="btn btn-sm btn-secondary" data-tm-id="${tm.id}">↻ Re-run analysis</button>
          ${(tm.owner_id === me.user.id || me.user.role === 'admin') ? `
            <button id="btn-delete-tm" class="btn btn-sm btn-danger" data-tm-id="${tm.id}">Delete</button>
          ` : ''}
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
      list.innerHTML = '<div class="text-center text-sm text-light" style="padding: 2rem;">No threats match filters</div>';
      return;
    }

    list.innerHTML = `
      <div class="text-xs text-light mb-2">Showing ${threats.length} of ${total} threats</div>
      ${threats.slice(0, 100).map((t, i) => {
        const status = (statuses[t.id] && statuses[t.id].status) || 'open';
        const cwe = t.cwe || {};
        const cvss31 = t.cvss31 || {};
        const owasp = (t.references || []).find(r => /A0\d/.test(r.label || ''));
        const dread = t.dread || {};
        const canEdit = (currentTM.owner_id === me.user.id || me.user.role === 'admin');

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
                ${canEdit ? `
                  <select data-status-select data-threat-id="${esc(t.id)}" class="select" style="font-size: 0.75rem; padding: 0.25rem 0.5rem; width: auto;" onclick="event.stopPropagation()">
                    <option value="open" ${status==='open'?'selected':''}>Open</option>
                    <option value="in_progress" ${status==='in_progress'?'selected':''}>In progress</option>
                    <option value="mitigated" ${status==='mitigated'?'selected':''}>Mitigated</option>
                    <option value="accepted_risk" ${status==='accepted_risk'?'selected':''}>Accepted</option>
                    <option value="false_positive" ${status==='false_positive'?'selected':''}>False positive</option>
                  </select>
                ` : `<span class="status status-${status}">${status.replace('_', ' ')}</span>`}
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
                    ${t.attack_scenario.map((s, i) => `
                      <div class="attack-step">
                        <div class="attack-step-num">${i+1}</div>
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

              <div class="mt-3" style="padding-top: 0.75rem; border-top: 1px solid var(--c-border);">
                <button class="show-history btn btn-sm btn-ghost" data-threat-id="${esc(t.id)}">View status history →</button>
                <div class="status-history mt-2 hidden"></div>
              </div>
            </div>
          </div>
        `;
      }).join('')}
      ${threats.length > 100 ? `<p class="text-xs text-center text-light mt-3">Showing first 100 of ${threats.length}. Download a report for the full list.</p>` : ''}
    `;

    list.querySelectorAll('.threat-header').forEach(h => {
      h.addEventListener('click', (e) => {
        if (e.target.closest('select')) return;
        const detail = h.parentElement.querySelector('.threat-detail');
        const icon = h.querySelector('.expand-icon');
        detail.classList.toggle('hidden');
        if (icon) icon.style.transform = detail.classList.contains('hidden') ? '' : 'rotate(180deg)';
      });
    });

    list.querySelectorAll('[data-status-select]').forEach(sel => {
      sel.addEventListener('change', async (e) => {
        e.stopPropagation();
        const threatId = sel.dataset.threatId;
        const newStatus = sel.value;
        const r = await Auth.fetch(`/api/threat-models/${currentTM.id}/threats/${threatId}/status`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ status: newStatus }),
        });
        if (r.ok) {
          UI.toast(`Status: ${newStatus.replace('_', ' ')}`, 'success', 1500);
          if (!currentTM.threat_statuses) currentTM.threat_statuses = {};
          currentTM.threat_statuses[threatId] = await r.json();
          const row = sel.closest('[data-threat-row]');
          row.className = row.className.replace(/status-\w+/g, '').trim();
          row.classList.add('threat-row', 'status-' + newStatus);
        } else {
          UI.toast('Failed to update', 'error');
        }
      });
    });

    list.querySelectorAll('.show-history').forEach(btn => {
      btn.addEventListener('click', async (e) => {
        e.stopPropagation();
        const threatId = btn.dataset.threatId;
        const container = btn.parentElement.querySelector('.status-history');
        if (!container.classList.contains('hidden')) {
          container.classList.add('hidden');
          btn.textContent = 'View status history →';
          return;
        }
        btn.textContent = 'Loading...';
        const r = await Auth.fetch(`/api/threat-models/${currentTM.id}/threats/${threatId}/history`);
        if (!r.ok) { btn.textContent = 'Failed to load'; return; }
        const history = await r.json();
        if (history.length === 0) {
          container.innerHTML = '<p class="text-xs text-light">No status changes yet</p>';
        } else {
          container.innerHTML = `
            <div class="flex-col gap-1">
              ${history.map(h => {
                const dur = h.duration_in_prev_seconds;
                const durStr = dur === null || dur === undefined ? '' : (
                  dur < 60 ? `${dur}s` :
                  dur < 3600 ? `${Math.round(dur/60)}m` :
                  dur < 86400 ? `${Math.round(dur/3600)}h` :
                  `${Math.round(dur/86400)}d`
                );
                return `
                  <div class="card p-2 flex items-center gap-2" style="font-size: 0.75rem;">
                    <span class="status status-${h.to_status}" style="font-size: 0.625rem;">${h.to_status.replace('_',' ')}</span>
                    ${h.from_status ? `<span class="text-light">from ${h.from_status.replace('_',' ')}</span>` : '<span class="text-light">first set</span>'}
                    ${durStr ? `<span class="text-light">(after ${durStr})</span>` : ''}
                    <span class="text-light">by ${esc(h.changed_by_email || '?')}</span>
                    <span class="text-light" style="margin-left: auto;">${(h.changed_at || '').slice(0,16).replace('T',' ')}</span>
                  </div>
                `;
              }).join('')}
            </div>
          `;
        }
        container.classList.remove('hidden');
        btn.textContent = 'Hide status history ↑';
      });
    });
  }

  function wireDetailActions() {
    document.querySelectorAll('.tab').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.tab').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        document.querySelectorAll('.tab-panel').forEach(p => p.classList.add('hidden'));
        document.getElementById('tab-' + btn.dataset.tab).classList.remove('hidden');
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
    if (search) search.addEventListener('input', (e) => { filter.search = e.target.value; renderThreats(); });
    const statusFilter = document.getElementById('threat-status-filter');
    if (statusFilter) statusFilter.addEventListener('change', (e) => { filter.status = e.target.value || null; renderThreats(); });
    const clearSev = document.getElementById('clear-sev-filter');
    if (clearSev) clearSev.addEventListener('click', () => { filter.severity = null; renderDetail(); });

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
        } catch {}
        btn.innerHTML = original;
      });
    });

    const rerunBtn = document.getElementById('btn-rerun');
    if (rerunBtn) rerunBtn.addEventListener('click', () => runAnalysis(rerunBtn));

    const runBtn = document.getElementById('btn-run-analysis');
    if (runBtn) runBtn.addEventListener('click', () => runAnalysis(runBtn));

    const delBtn = document.getElementById('btn-delete-tm');
    if (delBtn) delBtn.addEventListener('click', () => {
      UI.confirmDialog(`Permanently delete "${currentTM.name}"? This cannot be undone.`, async () => {
        const r = await Auth.fetch(`/api/threat-models/${currentTM.id}`, { method: 'DELETE' });
        if (r.ok) {
          UI.toast('Threat model deleted', 'success');
          UI.hideModal('modal-tm-detail');
          await loadAll();
        } else {
          UI.toast('Delete failed', 'error');
        }
      });
    });
  }

  async function runAnalysis(btn) {
    const original = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = '<span class="dots-loader"><span></span><span></span><span></span></span> Analyzing...';
    const r = await Auth.fetch(`/api/threat-models/${currentTM.id}/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ methodologies: currentTM.methodologies, use_llm: false }),
    });
    if (r.ok) {
      UI.toast('Analysis complete', 'success');
      const r2 = await Auth.fetch('/api/threat-models/' + currentTM.id);
      if (r2.ok) {
        currentTM = await r2.json();
        renderDetail();
      }
    } else {
      UI.toast('Analysis failed', 'error');
      btn.innerHTML = original;
      btn.disabled = false;
    }
  }

  let dfdEditor = null;
  let dfdDirty = false;

  async function loadDfd() {
    const container = document.getElementById('dfd-container');
    if (!container || container.dataset.loaded === '1') return;
    container.dataset.loaded = '1';
    container.innerHTML = '';

    if (!window.DfdEditor) {
      container.innerHTML = '<p style="color: var(--c-critical); font-size: 0.875rem; padding: 2rem;">DFD editor module failed to load. Please refresh the page.</p>';
      return;
    }

    const sourceText = (currentTM.system && currentTM.system._source_text) || currentTM.description || '';
    const canEdit = (currentTM.owner_id === me.user.id || me.user.role === 'admin');

    dfdEditor = window.DfdEditor.mount(container, currentTM.system || {}, {
      readOnly: !canEdit,
      sourceText: sourceText,
      onChange: () => {
        dfdDirty = true;
        const saveBtn = document.getElementById('btn-save-dfd');
        if (saveBtn && canEdit) saveBtn.classList.remove('hidden');
      },
    });

    // Save button handler
    const saveBtn = document.getElementById('btn-save-dfd');
    if (saveBtn && canEdit) {
      saveBtn.addEventListener('click', async () => {
        const updatedSystem = dfdEditor.getSystem();
        // Strip helper-only fields before saving
        delete updatedSystem._source_text;
        delete updatedSystem._boundary_inference_mode;
        const original = saveBtn.innerHTML;
        saveBtn.innerHTML = '<span class="spinner spinner-sm"></span> Saving...';
        saveBtn.disabled = true;
        try {
          const r = await Auth.fetch('/api/threat-models/' + currentTM.id, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ system: updatedSystem }),
          });
          if (!r.ok) {
            const data = await r.json().catch(() => ({}));
            throw new Error(UI.formatApiError(data, 'Save failed'));
          }
          currentTM.system = updatedSystem;
          dfdDirty = false;
          saveBtn.classList.add('hidden');
          UI.toast('DFD saved. Re-run analysis to refresh threats.', 'success');
        } catch (e) {
          UI.toast(e.message, 'error');
        } finally {
          saveBtn.innerHTML = original;
          saveBtn.disabled = false;
        }
      });
    }
  }

  loadAll();
})();
